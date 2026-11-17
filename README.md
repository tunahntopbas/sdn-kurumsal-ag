# SDN Kurumsal Ağ: Yük Dengeleme ve Anomali Tespiti

BSM-451 Ağ Programlama dersi proje ödevi, **Konu 3**: Mininet ve POX ile bir SDN ağı kurmak, kurumsal bir ağ yapısını (merkez ve şubeler) modellemek, trafik senaryoları üzerinde ağ uygulaması geliştirmek.

Bu projede:

- Mininet üzerinde **merkez ofis + 2 şubeden** oluşan bir kurumsal ağ var: 4 SDN switch, 3 Linux router, 3 web sunucusu ve 6 kullanıcı. Şubeler merkeze yavaş WAN hatlarıyla bağlı.
- Switch'leri tek bir **POX** denetleyicisi (OpenFlow 1.0) yönetiyor.
- Denetleyicinin içine iki uygulama yazıldı:
  - **Yük dengeleyici:** İstemciler tek bir sanal IP'ye (`10.0.1.100`) bağlanıyor. POX her yeni bağlantıyı sırayla (round robin) web1, web2 ve web3'e dağıtıyor.
  - **Anomali tespiti:** SYN flood ve port taramasını kaynak IP başına kayan pencereyle sayıyor. Eşik aşılınca switch'e saldırganın paketlerini düşüren bir kural yazıyor.
- `senaryo.py` 4 trafik senaryosunu otomatik çalıştırıp korumasız (`ders5`) ve korumalı (`ders6`) sürümü karşılaştırıyor.

## Topoloji

```
                         POX (127.0.0.1:6633)
                     OpenFlow ile s1-s4'ü yönetir

   web1 web2 web3            pc1 pc2
   .11  .12  .13             .11 .12
      \  |  /                  \ /
        s1 ------- r1 -------- s2
   10.0.1.0/24   /    \    10.0.2.0/24
   VIP .100     /      \
          WAN  /        \  WAN  (10 Mbit/s, 20 ms)
              r2        r3
              |          |
              s3         s4
         10.1.1.0/24  10.2.1.0/24
            /  \        /  \
         b1h1 b1h2   b2h1 b2h2
```

| Ağ | Alt ağ | Gateway | Switch | Cihazlar |
|---|---|---|---|---|
| Merkez sunucu | 10.0.1.0/24 | 10.0.1.1 (r1) | s1 | web1 .11, web2 .12, web3 .13, VIP .100 |
| Merkez kullanıcı | 10.0.2.0/24 | 10.0.2.1 (r1) | s2 | pc1 .11, pc2 .12 |
| Şube 1 | 10.1.1.0/24 | 10.1.1.1 (r2) | s3 | b1h1 .11, b1h2 .12 |
| Şube 2 | 10.2.1.0/24 | 10.2.1.1 (r3) | s4 | b2h1 .11, b2h2 .12 |
| WAN | 10.255.1.0/30, 10.255.2.0/30 | | | r1-r2, r1-r3 |

LAN bağlantıları 100 Mbit/s ve 1 ms, WAN bağlantıları 10 Mbit/s ve 20 ms.

## Dosyalar

| Dosya | Ne yapar |
|---|---|
| `kurumsal_ag.py` | Mininet topolojisi (`KurumsalTopo`), Linux router sınıfı, statik rotalar |
| `pox_modules/ders4.py` | Öğrenen switch: MAC öğrenme, packet-in logu, flow-mod |
| `pox_modules/ders5.py` | ders4 + sanal IP için proxy ARP + round robin yük dengeleme |
| `pox_modules/ders6.py` | ders5 + SYN flood / port taraması tespiti ve engelleme, akış bazlı kurallar |
| `pox_modules/ders6_62_yedek.py` | ders6'nın akış bazlı kural (6.3) öncesi sürümü |
| `senaryo.py` | 4 trafik senaryosunu çalıştırır, sonuçları `sonuclar/` klasörüne yazar |
| `sonuclar/` | Ölçüm sonuçları (`ders5`, `ders6`, `karsilastirma.md`) |
| `netem_keepalive.sh` | Apple Silicon Multipass VM'de WAN gecikmesini kararlı tutan yardımcı betik |
| `www/` | Web sunucularının örnek sayfaları |

## Gereksinimler

- Ubuntu (24.04 üzerinde denendi), Python 3
- Mininet, Open vSwitch
- POX (`~/pox`)
- Senaryolar için `hping3`, `nmap`, `curl`

```bash
sudo apt install mininet openvswitch-switch hping3 nmap curl
git clone https://github.com/noxrepo/pox ~/pox
```

POX modüllerini POX'un `ext/` klasörüne bağlayın:

```bash
ln -s ~/proje/pox_modules/ders4.py ~/pox/ext/ders4.py
ln -s ~/proje/pox_modules/ders5.py ~/pox/ext/ders5.py
ln -s ~/proje/pox_modules/ders6.py ~/pox/ext/ders6.py
```

## Çalıştırma

**1. terminal: denetleyici**

```bash
cd ~/pox
./pox.py ders6
```

**2. terminal: ağ**

```bash
cd ~/proje
sudo mn -c
sudo python3 kurumsal_ag.py
```

Mininet CLI'da deneyebileceğiniz komutlar:

```
mininet> pingall
mininet> web1 python3 -m http.server 80 --directory www/web1 &
mininet> pc1 curl 10.0.1.100
mininet> pc1 hping3 -S -p 80 -i u10000 -c 300 10.0.1.100
mininet> sh ovs-ofctl dump-flows s1
```

**Otomatik senaryolar ve karşılaştırma** (her çalıştırmadan önce POX'u yeniden başlatın):

```bash
sudo python3 senaryo.py ders5     # POX'ta ders5 çalışırken
sudo python3 senaryo.py ders6     # POX'ta ders6 çalışırken
sudo python3 senaryo.py karsilastir ders5 ders6
```

Apple Silicon üzerindeki Multipass VM'de ölçüm yapıyorsanız, WAN gecikmesi kararlı kalsın diye ölçümden önce `./netem_keepalive.sh start`, bitince `./netem_keepalive.sh stop` çalıştırın.

## Sonuçlar

| Senaryo | Metrik | ders5 (korumasız) | ders6 (korumalı) |
|---|---|---|---|
| S1 normal trafik | Dağılım web1 / web2 / web3 | 20 / 20 / 20 | 20 / 20 / 20 |
| S1 normal trafik | Başarısız istek | 0 | 0 |
| S2 SYN flood (300 SYN) | Cevaplanan SYN | 300 | 49 |
| S2 SYN flood | Switch'te düşen paket | 0 | 250 |
| S2 SYN flood | Akış tablosu, önce → tepe | 0 → 602 | 0 → 197 |
| S3 port taraması (VIP) | Keşfedilen port | 100 | 0 |
| S4 port taraması (doğrudan) | Keşfedilen port | 100 | 0 |

Tablonun tamamı: [`sonuclar/karsilastirma.md`](sonuclar/karsilastirma.md)

## Bilinen sınırlamalar

- Eşikler sabit (5 sn'de 50 SYN, 10 sn'de 10 farklı port). Yavaş taramalar yakalanmaz.
- Sayım kaynak IP başına yapılıyor, çok kaynaklı dağıtık saldırılar (DDoS) tespit edilmez.
- Engel kuralı yeni akışları durdurur. Alarmdan önce açılmış akışlar, süreleri dolana kadar (en fazla 30 sn) devam eder.
- Sunucu sağlık kontrolü yok: çöken bir sunucu seçilmeye devam eder.
- Tek denetleyici var. Denetleyici çökerse yeni akış kurulamaz.

## Sunum ve anlatım belgeleri

`docs/` klasöründe:

- [`SDN_Kurumsal_Ag_Sunum.html`](docs/SDN_Kurumsal_Ag_Sunum.html): 27 slaytlık sunum, tek dosya. Tarayıcıda açın; ← → ile slayt değiştirin, F tam ekran, N konuşmacı notları.
- [`proje-anlatimi.html`](docs/proje-anlatimi.html): projeyi sıfırdan anlatan sayfa.
- [`SDN_Kurumsal_Ag_Proje_Anlatimi.pdf`](docs/SDN_Kurumsal_Ag_Proje_Anlatimi.pdf): anlatım sayfasının PDF hali.
- [`sunum-kaynak/`](docs/sunum-kaynak/): sunumun kaynak slaytları. Tek dosyalık HTML'i yeniden üretmek için:
  `python3 docs/sunum-kaynak/build_standalone.py docs/sunum-kaynak docs/SDN_Kurumsal_Ag_Sunum.html`
