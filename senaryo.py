#!/usr/bin/env python3
"""
Ders 7 - Trafik senaryolari ve olcumler.

Kullanim (ayri terminalde POX calisirken):
  sudo mn -c
  sudo python3 senaryo.py ders6        # etiket: hangi POX modulu calisiyor
  sudo python3 senaryo.py karsilastir ders5 ders6

Betik kurumsal_ag.py'deki topolojiyi kendisi kurar (onceki Mininet'i kapat),
sirayla 4 senaryo calistirir, sonucu sonuclar/<etiket>.json ve .md dosyasina yazar.
"""

import json
import os
import re
import subprocess
import sys
import threading
import time

from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.link import TCLink
from mininet.log import setLogLevel

from kurumsal_ag import KurumsalTopo

KLASOR = os.path.dirname(os.path.abspath(__file__))
SONUC_KLASORU = os.path.join(KLASOR, "sonuclar")
WWW = "/tmp/senaryo_www"
VIP = "10.0.1.100"
BEKLEME = 35      # senaryolar arasi bekleme (sn): onceki kurallar (idle 30 sn) silinsin


# ----------------------------------------------------------------------
# Ag kurulumu
# ----------------------------------------------------------------------

def ag_kur():
  """Topolojiyi kurar, rotalari ekler, web sunucularini baslatir."""
  net = Mininet(topo=KurumsalTopo(), link=TCLink, controller=None)
  net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)
  net.start()
  net['r1'].cmd('ip route add 10.1.1.0/24 via 10.255.1.2')
  net['r1'].cmd('ip route add 10.2.1.0/24 via 10.255.2.2')
  net['r2'].cmd('ip route add default via 10.255.1.1')
  net['r3'].cmd('ip route add default via 10.255.2.1')
  return net


def sunuculari_baslat(net):
  for i in (1, 2, 3):
    klasor = "%s/web%d" % (WWW, i)
    os.makedirs(klasor, exist_ok=True)
    with open(klasor + "/index.html", "w") as f:
      f.write("Merhaba! Ben web%d sunucusuyum (10.0.1.1%d)\n" % (i, i))
    net['web%d' % i].cmd('python3 -m http.server 80 --directory %s >/dev/null 2>&1 &' % klasor)
  time.sleep(2)


def switchleri_bekle(net, sure=30):
  for _ in range(sure):
    if all(sw.connected() for sw in net.switches):
      return True
    time.sleep(1)
  return False


# ----------------------------------------------------------------------
# Olcum yardimcilari
# ----------------------------------------------------------------------

def curl(host, url):
  """(sunucu adi ya da None, gecikme ms) dondurur."""
  cikti = host.cmd("curl --noproxy '*' -s -m 5 -w '\\n%{time_total}' " + url).strip().splitlines()
  if not cikti:
    return None, 0.0
  m = re.search(r"Ben (web\d)", "\n".join(cikti[:-1]))   # son satir sure, gerisi sayfa
  try:
    ms = float(cikti[-1]) * 1000
  except ValueError:
    ms = 0.0
  return (m.group(1) if m else None), ms


def akis_tablosu():
  """Tum switch'lerin kurallari: {switch: [satir, ...]}."""
  sonuc = {}
  for sw in ("s1", "s2", "s3", "s4"):
    cikti = subprocess.run(["ovs-ofctl", "-O", "OpenFlow10", "dump-flows", sw],
                           capture_output=True, text=True).stdout
    sonuc[sw] = [l for l in cikti.splitlines() if "cookie=" in l]
  return sonuc


def tablo_boyutu():
  return sum(len(v) for v in akis_tablosu().values())


def engel_kurallari(tablo=None):
  """Drop kurallari: {kural anahtari: dusen paket}. Anahtar = eslesme metni."""
  sonuc = {}
  for satirlar in (tablo or akis_tablosu()).values():
    for l in satirlar:
      if "actions=drop" in l:
        anahtar = l.split("priority=")[-1].split(" actions")[0]
        m = re.search(r"n_packets=(\d+)", l)
        sonuc[anahtar] = int(m.group(1)) if m else 0
  return sonuc


class TabloIzleyici(threading.Thread):
  """Senaryo SURERKEN tabloyu ornekler; kurallar senaryo bitmeden silinebilir,
  bu yuzden sadece bitisteki degere bakmak yaniltir. Sadece senaryo SIRASINDA
  yazilan engel kurallarini sayar (onceki senaryolardan kalanlari degil)."""

  def __init__(self):
    super().__init__(daemon=True)
    self.dur = False
    self.onceki = set(engel_kurallari())
    self.tepe_tablo = 0
    self.yeni_engel = {}          # {anahtar: en yuksek dusen paket}

  @property
  def tepe_engel(self):
    return len(self.yeni_engel)

  @property
  def tepe_dusen(self):
    return sum(self.yeni_engel.values())

  def _ornekle(self, tablo):
    self.tepe_tablo = max(self.tepe_tablo, sum(len(v) for v in tablo.values()))
    for anahtar, paket in engel_kurallari(tablo).items():
      if anahtar not in self.onceki:
        self.yeni_engel[anahtar] = max(self.yeni_engel.get(anahtar, 0), paket)

  def run(self):
    while not self.dur:
      self._ornekle(akis_tablosu())
      time.sleep(0.3)

  def bitir(self):
    self.dur = True
    self.join()
    self._ornekle(akis_tablosu())   # son bir ornek


def hping_sonuc(cikti):
  m = re.search(r"(\d+) packets transmitted, (\d+) packets received", cikti)
  return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


def nmap_sonuc(cikti):
  """(acik port listesi, kapali sayisi, filtreli sayisi, sure sn)."""
  acik = [int(p) for p in re.findall(r"^(\d+)/tcp\s+open", cikti, re.M)]
  kapali = re.search(r"Not shown: (\d+) closed", cikti)
  filtreli = re.search(r"(\d+) filtered", cikti)
  sure = re.search(r"scanned in ([\d.]+) seconds", cikti)
  return (acik,
          int(kapali.group(1)) if kapali else 0,
          int(filtreli.group(1)) if filtreli else 0,
          float(sure.group(1)) if sure else 0.0)


def bekle(saniye):
  print("   ... %d sn bekleniyor (eski kurallar silinsin)" % saniye)
  time.sleep(saniye)


# ----------------------------------------------------------------------
# Senaryolar. Her biri satirlar listesine (senaryo, metrik, deger) ekler.
# ----------------------------------------------------------------------

def senaryo1_normal(net, satirlar):
  print("\n[S1] Normal trafik: 4 istemci x 15 istek -> VIP")
  sayac = {"web1": 0, "web2": 0, "web3": 0}
  basarisiz = 0
  for ad in ("pc1", "pc2", "b1h1", "b2h1"):
    gecikmeler = []
    for _ in range(15):
      sunucu, ms = curl(net[ad], "http://" + VIP)
      if sunucu is None:
        basarisiz += 1
      else:
        sayac[sunucu] += 1
        gecikmeler.append(ms)
    ort = sum(gecikmeler) / len(gecikmeler) if gecikmeler else 0
    print("   %-5s ortalama gecikme: %.1f ms" % (ad, ort))
    satirlar.append(("S1 normal", "ort. gecikme %s (ms)" % ad, "%.1f" % ort))
  print("   dagilim:", sayac, "| basarisiz:", basarisiz)
  satirlar.append(("S1 normal", "dagilim web1/web2/web3",
                   "%d / %d / %d" % (sayac["web1"], sayac["web2"], sayac["web3"])))
  satirlar.append(("S1 normal", "basarisiz istek", str(basarisiz)))


def senaryo2_syn_flood(net, satirlar):
  print("\n[S2] SYN flood: pc1 -> VIP, 100 SYN/sn, 300 paket")
  once = tablo_boyutu()
  izle = TabloIzleyici()
  izle.start()
  cikti = net['pc1'].cmd("hping3 -q -S -p 80 -i u10000 -c 300 %s" % VIP)
  izle.bitir()
  gonderilen, alinan = hping_sonuc(cikti)
  sunucu, _ = curl(net['pc2'], "http://" + VIP)
  print("   gonderilen %d, cevaplanan %d, engel kurali %d, dusen paket %d" %
        (gonderilen, alinan, izle.tepe_engel, izle.tepe_dusen))
  print("   tablo: %d -> tepe %d satir | baska istemci (pc2): %s" %
        (once, izle.tepe_tablo, "calisiyor" if sunucu else "ETKILENDI"))
  satirlar.append(("S2 SYN flood", "gonderilen SYN", str(gonderilen)))
  satirlar.append(("S2 SYN flood", "cevaplanan SYN", str(alinan)))
  satirlar.append(("S2 SYN flood", "engel kurali sayisi (tepe)", str(izle.tepe_engel)))
  satirlar.append(("S2 SYN flood", "switch'te dusen paket (tepe)", str(izle.tepe_dusen)))
  satirlar.append(("S2 SYN flood", "tablo boyutu once -> tepe", "%d -> %d" % (once, izle.tepe_tablo)))
  satirlar.append(("S2 SYN flood", "baska istemci etkilendi mi",
                   "hayir" if sunucu else "EVET"))


def senaryo3_tarama_vip(net, satirlar):
  print("\n[S3] Port taramasi (VIP uzerinden): pc2 -> 10.0.1.100, port 1-100")
  once = tablo_boyutu()
  izle = TabloIzleyici()
  izle.start()
  cikti = net['pc2'].cmd("nmap -Pn -sS -p 1-100 --max-retries 1 %s" % VIP)
  izle.bitir()
  acik, kapali, filtreli, sure = nmap_sonuc(cikti)
  kesfedilen = len(acik) + kapali
  print("   acik %s, kapali %d, filtreli %d, sure %.1f sn, kesfedilen port %d" %
        (acik, kapali, filtreli, sure, kesfedilen))
  print("   tablo: %d -> tepe %d satir, engel kurali (tepe) %d" %
        (once, izle.tepe_tablo, izle.tepe_engel))
  satirlar.append(("S3 tarama (VIP)", "kesfedilen port (acik+kapali)", str(kesfedilen)))
  satirlar.append(("S3 tarama (VIP)", "acik port", ",".join(map(str, acik)) or "-"))
  satirlar.append(("S3 tarama (VIP)", "filtreli (cevapsiz) port", str(filtreli)))
  satirlar.append(("S3 tarama (VIP)", "engel kurali sayisi (tepe)", str(izle.tepe_engel)))
  satirlar.append(("S3 tarama (VIP)", "tablo boyutu once -> tepe", "%d -> %d" % (once, izle.tepe_tablo)))


def senaryo4_tarama_dogrudan(net, satirlar):
  print("\n[S4] Port taramasi (sunucuya DOGRUDAN, kural canli): b1h2 -> 10.0.1.11")
  # hafif trafik: MAC/akis kurallari tabloda canli kalsin (kor nokta senaryosu)
  net['b1h2'].cmd("ping -c 40 -i 0.4 -q 10.0.1.11 >/dev/null 2>&1 &")
  time.sleep(3)
  izle = TabloIzleyici()
  izle.start()
  cikti = net['b1h2'].cmd("nmap -Pn -sS -p 1-100 --max-retries 1 10.0.1.11")
  izle.bitir()
  acik, kapali, filtreli, sure = nmap_sonuc(cikti)
  kesfedilen = len(acik) + kapali
  print("   acik %s, kapali %d, filtreli %d, sure %.1f sn, kesfedilen port %d" %
        (acik, kapali, filtreli, sure, kesfedilen))
  print("   engel kurali (tepe) %d" % izle.tepe_engel)
  satirlar.append(("S4 tarama (dogrudan)", "kesfedilen port (acik+kapali)", str(kesfedilen)))
  satirlar.append(("S4 tarama (dogrudan)", "acik port", ",".join(map(str, acik)) or "-"))
  satirlar.append(("S4 tarama (dogrudan)", "filtreli (cevapsiz) port", str(filtreli)))
  satirlar.append(("S4 tarama (dogrudan)", "engel kurali sayisi (tepe)", str(izle.tepe_engel)))


# ----------------------------------------------------------------------
# Sonuc yazimi
# ----------------------------------------------------------------------

def tablo_yaz(baslik_kolonlar, satirlar):
  """Markdown tablo metni."""
  cikti = ["| " + " | ".join(baslik_kolonlar) + " |",
           "|" + "---|" * len(baslik_kolonlar)]
  for s in satirlar:
    cikti.append("| " + " | ".join(s) + " |")
  return "\n".join(cikti)


def kaydet(etiket, satirlar):
  os.makedirs(SONUC_KLASORU, exist_ok=True)
  with open(os.path.join(SONUC_KLASORU, etiket + ".json"), "w") as f:
    json.dump({"etiket": etiket, "tarih": time.strftime("%Y-%m-%d %H:%M"),
               "satirlar": satirlar}, f, ensure_ascii=False, indent=1)
  md = tablo_yaz(["Senaryo", "Metrik", etiket], [list(s) for s in satirlar])
  with open(os.path.join(SONUC_KLASORU, etiket + ".md"), "w") as f:
    f.write(md + "\n")
  print("\n" + md)
  print("\nKaydedildi: sonuclar/%s.json ve .md" % etiket)


def karsilastir(etiket_a, etiket_b):
  veri = {}
  for e in (etiket_a, etiket_b):
    with open(os.path.join(SONUC_KLASORU, e + ".json")) as f:
      veri[e] = {(s[0], s[1]): s[2] for s in json.load(f)["satirlar"]}
  anahtarlar = list(veri[etiket_a].keys())
  satirlar = [[s, m, veri[etiket_a].get((s, m), "-"), veri[etiket_b].get((s, m), "-")]
              for (s, m) in anahtarlar]
  md = tablo_yaz(["Senaryo", "Metrik", etiket_a, etiket_b], satirlar)
  with open(os.path.join(SONUC_KLASORU, "karsilastirma.md"), "w") as f:
    f.write(md + "\n")
  print(md)
  print("\nKaydedildi: sonuclar/karsilastirma.md")


def main():
  if len(sys.argv) == 4 and sys.argv[1] == "karsilastir":
    karsilastir(sys.argv[2], sys.argv[3])
    return
  if len(sys.argv) != 2:
    print(__doc__)
    sys.exit(1)
  etiket = sys.argv[1]

  setLogLevel('warning')
  net = ag_kur()
  satirlar = []
  try:
    print("Switch'ler POX'a baglaniyor...")
    if not switchleri_bekle(net):
      print("HATA: switch'ler POX'a baglanamadi. POX calisiyor mu?")
      return
    sunuculari_baslat(net)
    time.sleep(3)
    sunucu, _ = curl(net['pc2'], "http://" + VIP)
    print("On kontrol (pc2 -> VIP):", sunucu or "YANIT YOK")
    if sunucu is None:
      print("HATA: VIP cevap vermiyor, senaryolar atlandi.")
      return
    # On kontrol yuk dengeleme sayacini bir ilerletti; POX'u yeniden baslatmadan
    # tekrar calistirirsan dagilim kayabilir. Her calistirmadan once POX'u yeniden baslat.

    for senaryo in (senaryo1_normal, senaryo2_syn_flood,
                    senaryo3_tarama_vip, senaryo4_tarama_dogrudan):
      senaryo(net, satirlar)
      if senaryo is not senaryo4_tarama_dogrudan:
        bekle(BEKLEME)
    kaydet(etiket, satirlar)
  finally:
    net.stop()


if __name__ == '__main__':
  main()
