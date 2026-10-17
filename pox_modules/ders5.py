"""
Ders 5 - Adim 5.3: Yuk dengeleme (sanal IP -> 3 sunucu, round robin).

Ders 4'teki "ogrenen switch" mantigina uc sey eklenir:
  1) Sanal IP (VIP) icin ARP cevabi            (adim 5.2)
  2) Sunucularin MAC adreslerini ogrenme       (adim 5.3)
  3) VIP'e gelen her yeni baglantiyi siradaki sunucuya yonlendirme.
     Switch'e iki kural yazilir:
       - GIDIS : istemci -> VIP  paketinin hedefi, secilen sunucuya cevrilir
       - DONUS : sunucu -> istemci paketinin kaynagi, VIP'e cevrilir

Calistirma (POX klasorunden):
  ./pox.py ders5
"""

import time

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp

log = core.getLogger()

# Normal (Ders 4) kurallarin omru (saniye)
IDLE_TIMEOUT = 10
HARD_TIMEOUT = 30

# --- Ders 5: sanal IP ayarlari ---
SANAL_IP = IPAddr("10.0.1.100")
SANAL_MAC = EthAddr("02:00:00:00:01:00")

# --- YENI (5.3): yuk dengeleme ayarlari ---
SUNUCULAR = [IPAddr("10.0.1.11"), IPAddr("10.0.1.12"), IPAddr("10.0.1.13")]
LB_SWITCH_DPID = 1        # sunuculari goren switch: s1 (DPID 00-00-00-00-00-01)
# Yuk dengeleme kurallari: 30 sn bosta kalirsa silinir, ust sinir YOK (0).
# Ust sinir olsaydi uzun suren bir baglanti ortasinda baska sunucuya kayabilirdi.
LB_IDLE_TIMEOUT = 30
LB_HARD_TIMEOUT = 0
# Oncelik: yuk dengeleme kurallari normal (L2) kurallardan (32768) ONCE
# uygulanmali. Ayni oncelikte olsalardi switch hangisini sececegini garanti
# etmez ve cevap paketi VIP'e cevrilmeden gidebilirdi.
LB_ONCELIK = 40000
# Akis hafizasi: bir TCP baglantisinin hangi sunucuya atandigini bu kadar
# saniye hatirla (kural silinse bile baglanti ayni sunucuda kalsin).
LB_HAFIZA = 120


class Ders5Switch(object):
  """Tek bir switch'in beyni. Her switch icin bir tane olusturulur."""

  def __init__(self, connection):
    self.connection = connection
    self.dpid = connection.dpid
    self.mac_to_port = {}      # {MAC: switch portu}
    self.ip_to_mac = {}        # YENI: {sunucu IP: sunucu MAC}
    self.siradaki = 0          # YENI: round robin sayaci
    self.akislar = {}          # YENI: {akis anahtari: (sunucu IP, son zaman)}
    self.lb_aktif = (self.dpid == LB_SWITCH_DPID)   # YENI
    self.packet_in_sayisi = 0
    connection.addListeners(self)
    if self.lb_aktif:
      # Baglanir baglanmaz sunucularin MAC'lerini ogrenelim
      self._sunuculari_sor()

  def _handle_PacketIn(self, event):
    packet = event.parsed
    if not packet.parsed:
      log.warning("%s: eksik paket, atlandi", dpid_to_str(self.dpid))
      return

    self.packet_in_sayisi += 1
    in_port = event.port

    # 1) Log: paketin ozeti
    log.info("PACKET-IN #%d  switch=%s port=%s  %s",
             self.packet_in_sayisi, dpid_to_str(self.dpid), in_port,
             self._ozet(packet))

    # 2) Ogren: kaynak MAC bu portta
    self.mac_to_port[packet.src] = in_port

    # 3) ARP paketleri
    arp_p = packet.find('arp')
    if arp_p is not None:
      # YENI: gonderen bir sunucuysa IP -> MAC bilgisini ogren
      if arp_p.protosrc in SUNUCULAR:
        self.ip_to_mac[arp_p.protosrc] = arp_p.hwsrc
      # Biri sanal IP'yi soruyorsa kendimiz cevaplayalim (adim 5.2)
      if arp_p.opcode == arp.REQUEST and arp_p.protodst == SANAL_IP:
        self._vip_icin_arp_cevapla(event, arp_p)
        return
      # YENI: bizim sorumuza gelen cevap; ogrendik, baska yere dagitma
      if arp_p.opcode == arp.REPLY and packet.dst == SANAL_MAC:
        return

    # 4) YENI: sanal IP'ye giden IP paketi mi? Yuk dengele.
    ip = packet.find('ipv4')
    if self.lb_aktif and ip is not None and ip.dstip == SANAL_IP:
      self._yuk_dengele(event, packet, ip)
      return

    # 5) Karar ver (Ders 4 ile ayni)
    if packet.dst.is_multicast:
      self._flood(event)
      return

    out_port = self.mac_to_port.get(packet.dst)
    if out_port is None:
      self._flood(event)
      return

    if out_port == in_port:
      log.debug("giris ve cikis portu ayni, paket atiliyor")
      return

    self._kural_yaz(event, packet, out_port)

  def _ozet(self, packet):
    """Paketi tek satirda anlat: MAC, IP, protokol."""
    parcalar = ["%s -> %s" % (packet.src, packet.dst)]
    ip = packet.find('ipv4')
    arp_p = packet.find('arp')
    if ip:
      parcalar.append("IP %s -> %s" % (ip.srcip, ip.dstip))
      if packet.find('icmp'):
        parcalar.append("ICMP")
      elif packet.find('tcp'):
        tcp = packet.find('tcp')
        bayraklar = [ad for ad, var in (("SYN", tcp.SYN), ("ACK", tcp.ACK),
                                        ("FIN", tcp.FIN), ("RST", tcp.RST),
                                        ("PSH", tcp.PSH)) if var]
        parcalar.append("TCP %s->%s [%s]" % (tcp.srcport, tcp.dstport,
                                             "+".join(bayraklar)))
      elif packet.find('udp'):
        udp = packet.find('udp')
        parcalar.append("UDP %s->%s" % (udp.srcport, udp.dstport))
    elif arp_p:
      parcalar.append("ARP %s kimde? (soran %s)" % (arp_p.protodst, arp_p.protosrc)
                      if arp_p.opcode == arp.REQUEST else
                      "ARP cevap %s = %s" % (arp_p.protosrc, arp_p.hwsrc))
    else:
      parcalar.append("ethertype=0x%04x" % packet.type)
    return "  ".join(parcalar)

  def _vip_icin_arp_cevapla(self, event, istek):
    """'SANAL_IP kimde?' sorusuna POX adina cevap uret ve gonder."""
    cevap = arp()
    cevap.opcode = arp.REPLY
    cevap.hwsrc = SANAL_MAC          # cevabi veren: sanal MAC
    cevap.protosrc = SANAL_IP        # ... ve sanal IP
    cevap.hwdst = istek.hwsrc        # cevabin gidecegi: soran
    cevap.protodst = istek.protosrc

    cerceve = ethernet(type=ethernet.ARP_TYPE, src=SANAL_MAC, dst=istek.hwsrc)
    cerceve.payload = cevap

    msg = of.ofp_packet_out()
    msg.data = cerceve.pack()
    msg.in_port = event.port
    msg.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
    self.connection.send(msg)
    log.info("ARP-CEVAP  switch=%s  %s kimde? soran %s  ->  cevap: %s",
             dpid_to_str(self.dpid), SANAL_IP, istek.protosrc, SANAL_MAC)

  # ------------------------------------------------------------------
  # YENI (5.3): yuk dengeleme
  # ------------------------------------------------------------------

  def _sunuculari_sor(self):
    """Her sunucu icin 'su IP kimde?' diye ARP sorusu yayinla.
    Cevaplar PacketIn olarak geri gelir ve ip_to_mac tablosunu doldurur."""
    for sunucu_ip in SUNUCULAR:
      soru = arp()
      soru.opcode = arp.REQUEST
      soru.hwsrc = SANAL_MAC
      soru.protosrc = SANAL_IP
      soru.hwdst = EthAddr("00:00:00:00:00:00")
      soru.protodst = sunucu_ip
      cerceve = ethernet(type=ethernet.ARP_TYPE, src=SANAL_MAC,
                         dst=EthAddr("ff:ff:ff:ff:ff:ff"))
      cerceve.payload = soru
      msg = of.ofp_packet_out()
      msg.data = cerceve.pack()
      msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
      self.connection.send(msg)
    log.info("ARP-SOR    switch=%s  sunucularin MAC'leri soruluyor",
             dpid_to_str(self.dpid))

  def _sunucu_bilgisi(self, sunucu_ip):
    """Sunucunun MAC'i ve portu biliniyorsa (ip, mac, port) dondurur."""
    sunucu_mac = self.ip_to_mac.get(sunucu_ip)
    if sunucu_mac is not None and sunucu_mac in self.mac_to_port:
      return sunucu_ip, sunucu_mac, self.mac_to_port[sunucu_mac]
    return None

  def _sunucu_sec(self, anahtar):
    """Sunucu sec. Dondurur: (bilgi, yeni_mi) ya da (None, False).
    1) Bu akis daha once bir sunucuya atandiysa AYNI sunucuda kal
       (baglanti ortasinda sunucu degisirse baglanti kopar).
    2) Yeni akissa round robin: siradaki sunucu; MAC'i bilinmeyeni atla."""
    simdi = time.time()
    if anahtar is not None:
      kayit = self.akislar.get(anahtar)
      if kayit is not None and simdi - kayit[1] < LB_HAFIZA:
        bilgi = self._sunucu_bilgisi(kayit[0])
        if bilgi is not None:
          self.akislar[anahtar] = (kayit[0], simdi)
          return bilgi, False
    for _ in range(len(SUNUCULAR)):
      sunucu_ip = SUNUCULAR[self.siradaki % len(SUNUCULAR)]
      self.siradaki += 1
      bilgi = self._sunucu_bilgisi(sunucu_ip)
      if bilgi is not None:
        if anahtar is not None:
          self.akislar[anahtar] = (sunucu_ip, simdi)
        return bilgi, True
    return None, False

  def _yuk_dengele(self, event, packet, ip):
    """VIP'e gelen yeni bir akis icin sunucu sec ve iki kural yaz."""
    tcp = packet.find('tcp')
    icmp = packet.find('icmp')
    if tcp is None and icmp is None:
      log.warning("VIP'e desteklenmeyen protokol (%s), paket atildi", ip.protocol)
      return

    # Akis anahtari: (istemci IP, istemci portu, sunucu portu). Sadece TCP
    # icin tutulur; ICMP'de "baglanti" kavrami yok.
    anahtar = None
    if tcp is not None:
      anahtar = (ip.srcip, tcp.srcport, tcp.dstport)

    secim, yeni_mi = self._sunucu_sec(anahtar)
    if secim is None:
      log.warning("Hicbir sunucunun MAC'i bilinmiyor, paket atildi; ARP ile soruluyor")
      self._sunuculari_sor()
      return
    sunucu_ip, sunucu_mac, sunucu_port = secim
    istemci_port = event.port        # cevap bu porttan geri donecek

    # --- 1) DONUS kurali: sunucu -> istemci, kaynak VIP'e cevrilir ---
    geri = of.ofp_flow_mod()
    geri.match = of.ofp_match()
    geri.match.in_port = sunucu_port
    geri.match.dl_type = ethernet.IP_TYPE
    geri.match.nw_proto = ip.protocol
    geri.match.nw_src = sunucu_ip
    geri.match.nw_dst = ip.srcip
    if tcp is not None:
      geri.match.tp_src = tcp.dstport     # sunucunun portu (orn. 80)
      geri.match.tp_dst = tcp.srcport     # istemcinin portu
    else:
      geri.match.tp_src = 0               # ICMP tip 0 (echo reply)
      geri.match.tp_dst = 0               # ICMP kod 0
    geri.priority = LB_ONCELIK
    geri.idle_timeout = LB_IDLE_TIMEOUT
    geri.hard_timeout = LB_HARD_TIMEOUT
    geri.actions.append(of.ofp_action_dl_addr.set_src(SANAL_MAC))
    geri.actions.append(of.ofp_action_nw_addr.set_src(SANAL_IP))
    geri.actions.append(of.ofp_action_output(port=istemci_port))
    self.connection.send(geri)

    # --- 2) GIDIS kurali: istemci -> VIP, hedef secilen sunucuya cevrilir ---
    ileri = of.ofp_flow_mod()
    ileri.match = of.ofp_match.from_packet(packet, event.port)
    ileri.priority = LB_ONCELIK
    ileri.idle_timeout = LB_IDLE_TIMEOUT
    ileri.hard_timeout = LB_HARD_TIMEOUT
    ileri.actions.append(of.ofp_action_dl_addr.set_dst(sunucu_mac))
    ileri.actions.append(of.ofp_action_nw_addr.set_dst(sunucu_ip))
    ileri.actions.append(of.ofp_action_output(port=sunucu_port))
    ileri.data = event.ofp            # bekleyen ilk paket de bu kuralla gitsin
    self.connection.send(ileri)

    if tcp is not None:
      akis = "TCP %s:%s -> %s:%s" % (ip.srcip, tcp.srcport, SANAL_IP, tcp.dstport)
    else:
      akis = "ICMP %s -> %s" % (ip.srcip, SANAL_IP)
    log.info("YUK-DENGELE switch=%s  %s  ==>  sunucu %s (port %s)  [%s]",
             dpid_to_str(self.dpid), akis, sunucu_ip, sunucu_port,
             "yeni akis" if yeni_mi else "ayni sunucuda kaldi")

  # ------------------------------------------------------------------

  def _flood(self, event):
    """Paketi gelen port haric tum portlardan gonder."""
    msg = of.ofp_packet_out()
    msg.data = event.ofp
    msg.in_port = event.port
    msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
    self.connection.send(msg)

  def _kural_yaz(self, event, packet, out_port):
    """flow-mod: switch'e 'bu kaynak/hedef cifti icin su porttan cik' kurali yaz."""
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match()
    msg.match.dl_src = packet.src
    msg.match.dl_dst = packet.dst
    msg.idle_timeout = IDLE_TIMEOUT
    msg.hard_timeout = HARD_TIMEOUT
    msg.actions.append(of.ofp_action_output(port=out_port))
    # Kuralin yaninda, bekleyen ilk paketi de gonder
    msg.data = event.ofp
    self.connection.send(msg)
    log.info("FLOW-MOD   switch=%s  %s -> %s  cikis portu=%s",
             dpid_to_str(self.dpid), packet.src, packet.dst, out_port)


def launch():
  def baglandi(event):
    log.info("Switch baglandi: %s", dpid_to_str(event.dpid))
    Ders5Switch(event.connection)

  core.openflow.addListenerByName("ConnectionUp", baglandi)
  log.info("ders5 modulu calisiyor (sanal IP: %s, sunucular: %s)",
           SANAL_IP, ", ".join(str(s) for s in SUNUCULAR))
