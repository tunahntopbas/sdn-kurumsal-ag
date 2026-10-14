#!/usr/bin/env python3
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import Node, RemoteController
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel


class LinuxRouter(Node):
    """IP yönlendirmesi açık Linux host'u: router görevi görür."""
    def config(self, **params):
        super().config(**params)
        self.cmd('sysctl -w net.ipv4.ip_forward=1')

    def terminate(self):
        self.cmd('sysctl -w net.ipv4.ip_forward=0')
        super().terminate()


class KurumsalTopo(Topo):
    def build(self):
        lan = dict(bw=100, delay='1ms')
        wan = dict(bw=10, delay='20ms')

        # Router'lar
        r1 = self.addNode('r1', cls=LinuxRouter, ip=None)   # merkez
        r2 = self.addNode('r2', cls=LinuxRouter, ip=None)   # şube 1
        r3 = self.addNode('r3', cls=LinuxRouter, ip=None)   # şube 2

        # SDN switch'leri (POX yönetecek)
        s1 = self.addSwitch('s1')   # merkez sunucu ağı
        s2 = self.addSwitch('s2')   # merkez kullanıcı ağı
        s3 = self.addSwitch('s3')   # şube 1
        s4 = self.addSwitch('s4')   # şube 2

        # Sunucular
        web1 = self.addHost('web1', ip='10.0.1.11/24', defaultRoute='via 10.0.1.1')
        web2 = self.addHost('web2', ip='10.0.1.12/24', defaultRoute='via 10.0.1.1')
        web3 = self.addHost('web3', ip='10.0.1.13/24', defaultRoute='via 10.0.1.1')

        # Kullanıcılar
        pc1  = self.addHost('pc1',  ip='10.0.2.11/24', defaultRoute='via 10.0.2.1')
        pc2  = self.addHost('pc2',  ip='10.0.2.12/24', defaultRoute='via 10.0.2.1')
        b1h1 = self.addHost('b1h1', ip='10.1.1.11/24', defaultRoute='via 10.1.1.1')
        b1h2 = self.addHost('b1h2', ip='10.1.1.12/24', defaultRoute='via 10.1.1.1')
        b2h1 = self.addHost('b2h1', ip='10.2.1.11/24', defaultRoute='via 10.2.1.1')
        b2h2 = self.addHost('b2h2', ip='10.2.1.12/24', defaultRoute='via 10.2.1.1')

        # Switch - router bağlantıları (her router arayüzüne IP veriyoruz)
        self.addLink(s1, r1, intfName2='r1-eth1', params2={'ip': '10.0.1.1/24'}, **lan)
        self.addLink(s2, r1, intfName2='r1-eth2', params2={'ip': '10.0.2.1/24'}, **lan)
        self.addLink(s3, r2, intfName2='r2-eth2', params2={'ip': '10.1.1.1/24'}, **lan)
        self.addLink(s4, r3, intfName2='r3-eth2', params2={'ip': '10.2.1.1/24'}, **lan)

        # WAN: merkez router - şube router'ları
        self.addLink(r1, r2, intfName1='r1-eth3', intfName2='r2-eth1',
                     params1={'ip': '10.255.1.1/30'}, params2={'ip': '10.255.1.2/30'}, **wan)
        self.addLink(r1, r3, intfName1='r1-eth4', intfName2='r3-eth1',
                     params1={'ip': '10.255.2.1/30'}, params2={'ip': '10.255.2.2/30'}, **wan)

        # Host - switch bağlantıları
        for sunucu in (web1, web2, web3):
            self.addLink(sunucu, s1, **lan)
        for kullanici in (pc1, pc2):
            self.addLink(kullanici, s2, **lan)
        for kullanici in (b1h1, b1h2):
            self.addLink(kullanici, s3, **lan)
        for kullanici in (b2h1, b2h2):
            self.addLink(kullanici, s4, **lan)


def calistir():
    net = Mininet(topo=KurumsalTopo(), link=TCLink, controller=None)
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)
    net.start()

    # Statik rotalar
    net['r1'].cmd('ip route add 10.1.1.0/24 via 10.255.1.2')
    net['r1'].cmd('ip route add 10.2.1.0/24 via 10.255.2.2')
    net['r2'].cmd('ip route add default via 10.255.1.1')
    net['r3'].cmd('ip route add default via 10.255.2.1')

    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    calistir()
