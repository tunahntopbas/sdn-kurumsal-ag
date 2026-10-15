"""
Ders 4: Kendi POX modulumuz.

Ne yapar?
  1. Bir switch kontrolore baglaninca log basar.
  2. Her packet-in mesajinda: hangi switch, hangi port, kimden kime
     (MAC, IP, protokol) bilgisini log'a yazar.
  3. MAC adreslerini ogrenir (hangi MAC hangi portta).
  4. Hedef biliniyorsa switch'e flow kurali yazar (flow-mod),
     bilinmiyorsa paketi tum portlara dagitir (flood).

Calistirma (POX klasorunden):
  ./pox.py ders4
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str

log = core.getLogger()

# Yazilan kuralin bosta kalinca silinme suresi (saniye)
IDLE_TIMEOUT = 10
HARD_TIMEOUT = 30


class Ders4Switch(object):
  """Tek bir switch'in beyni. Her switch icin bir tane olusturulur."""

  def __init__(self, connection):
    self.connection = connection
    self.dpid = connection.dpid
    self.mac_to_port = {}      # {MAC: switch portu}
    self.packet_in_sayisi = 0
    # Bu switch'ten gelen olaylari (PacketIn gibi) dinle
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

    # 3) Karar ver
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
    arp = packet.find('arp')
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
    elif arp:
      parcalar.append("ARP %s kimde? (soran %s)" % (arp.protodst, arp.protosrc)
                      if arp.opcode == arp.REQUEST else
                      "ARP cevap %s = %s" % (arp.protosrc, arp.hwsrc))
    else:
      parcalar.append("ethertype=0x%04x" % packet.type)
    return "  ".join(parcalar)

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
    Ders4Switch(event.connection)

  core.openflow.addListenerByName("ConnectionUp", baglandi)
  log.info("ders4 modulu calisiyor")
