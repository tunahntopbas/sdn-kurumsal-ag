"""
Ders 5 - Adim 5.2: Sanal IP (VIP) icin ARP cevabi.

Ders 4'teki "ogrenen switch" mantigina tek bir sey ekler:
  Biri "10.0.1.100 kimde?" diye ARP ile sorarsa, POX bu soruya kendisi
  cevap verir ("10.0.1.100 bende, MAC'i su"). Boylece sanal IP, agda
  gercek bir cihazmis gibi gorunur. (Yuk dagitma adimi 5.3'te eklenecek.)

Calistirma (POX klasorunden):
  ./pox.py ders5
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp

log = core.getLogger()

# Yazilan kuralin bosta kalinca / en fazla silinme suresi (saniye)
IDLE_TIMEOUT = 10
HARD_TIMEOUT = 30

# --- YENI (Ders 5): sanal IP ayarlari ---
# Istemcilerin baglanacagi tek adres. Hicbir makinede tanimli degil.
SANAL_IP = IPAddr("10.0.1.100")
# Sanal IP'nin "MAC adresi". Uydurma bir adres; ilk bayt 02 olunca
# "yerel olarak atanmis, tekil (unicast)" bir MAC olur.
SANAL_MAC = EthAddr("02:00:00:00:01:00")


class Ders5Switch(object):
  """Tek bir switch'in beyni. Her switch icin bir tane olusturulur."""

  def __init__(self, connection):
    self.connection = connection
    self.dpid = connection.dpid
    self.mac_to_port = {}      # {MAC: switch portu}
    self.packet_in_sayisi = 0
    connection.addListeners(self)

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

    # 3) YENI: biri sanal IP'yi ARP ile soruyorsa kendimiz cevaplayalim
    istek = packet.find('arp')
    if (istek is not None and istek.opcode == arp.REQUEST
            and istek.protodst == SANAL_IP):
      self._vip_icin_arp_cevapla(event, istek)
      return

    # 4) Karar ver (Ders 4 ile ayni)
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
        parcalar.append("TCP %s->%s" % (tcp.srcport, tcp.dstport))
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
    """YENI: 'SANAL_IP kimde?' sorusuna POX adina cevap uret ve gonder."""
    # 1) ARP cevabinin icerigi: "SANAL_IP'nin MAC'i SANAL_MAC'tir"
    cevap = arp()
    cevap.opcode = arp.REPLY
    cevap.hwsrc = SANAL_MAC          # cevabi veren: sanal MAC
    cevap.protosrc = SANAL_IP        # ... ve sanal IP
    cevap.hwdst = istek.hwsrc        # cevabin gidecegi: soran
    cevap.protodst = istek.protosrc

    # 2) ARP'yi bir Ethernet cercevesine koy (kimden kime)
    cerceve = ethernet(type=ethernet.ARP_TYPE, src=SANAL_MAC, dst=istek.hwsrc)
    cerceve.payload = cevap

    # 3) Switch'e "bu cerceveyi geldigi porttan geri gonder" de
    msg = of.ofp_packet_out()
    msg.data = cerceve.pack()
    msg.in_port = event.port
    msg.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
    self.connection.send(msg)
    log.info("ARP-CEVAP  switch=%s  %s kimde? soran %s  ->  cevap: %s",
             dpid_to_str(self.dpid), SANAL_IP, istek.protosrc, SANAL_MAC)

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
  log.info("ders5 modulu calisiyor (sanal IP: %s, sanal MAC: %s)", SANAL_IP, SANAL_MAC)
