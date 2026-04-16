"""
SDN Firewall - Custom Mininet Topology
======================================
  h1 (10.0.0.1)  ─┐
  h2 (10.0.0.2)  ─┤── s1 ── (Ryu Controller @ 127.0.0.1:6633)
  h3 (10.0.0.3)  ─┤
  h4 (10.0.0.4)  ─┘

Run:   sudo python3 topology.py
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink


class FirewallTopo(Topo):
    """Single-switch topology with 4 hosts."""

    def build(self):
        # One OpenFlow switch
        s1 = self.addSwitch('s1', protocols='OpenFlow13')

        # Hosts — assign static IPs and MACs for easy identification
        h1 = self.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
        h3 = self.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
        h4 = self.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')

        # Links (100 Mbps, 1 ms delay — realistic-ish)
        opts = dict(bw=100, delay='1ms')
        self.addLink(h1, s1, **opts)
        self.addLink(h2, s1, **opts)
        self.addLink(h3, s1, **opts)
        self.addLink(h4, s1, **opts)


def run():
    topo = FirewallTopo()
    net  = Mininet(
        topo=topo,
        switch=OVSKernelSwitch,
        controller=None,     # we add it manually below
        link=TCLink,
        autoSetMacs=False
    )

    # Attach the remote Ryu controller
    c0 = net.addController(
        'c0',
        controller=RemoteController,
        ip='127.0.0.1',
        port=6633
    )

    net.start()

    # ── Print topology summary ────────────────────────────────────────────
    info('\n' + '=' * 50 + '\n')
    info('  SDN-Based Firewall Topology\n')
    info('=' * 50 + '\n')
    info('  h1  10.0.0.1  — Trusted Host A\n')
    info('  h2  10.0.0.2  — Trusted Host B\n')
    info('  h3  10.0.0.3  — UNTRUSTED Host (blocked → h4)\n')
    info('  h4  10.0.0.4  — Server\n')
    info('=' * 50 + '\n')
    info('  Firewall Rules:\n')
    info('    R1  BLOCK  h3 → h4  (all traffic)\n')
    info('    R2  BLOCK  h3 → any TCP:5001 (iperf)\n')
    info('    --  ALLOW  all other traffic\n')
    info('=' * 50 + '\n\n')

    # ── Quick automated test ──────────────────────────────────────────────
    info('Running initial pingall to populate ARP tables...\n')
    net.pingAll()

    info('\nDropping into Mininet CLI — run your tests here.\n')
    info('Useful commands:\n')
    info('  pingall                          # test all connectivity\n')
    info('  h1 ping -c3 h4                  # allowed (h1 → h4)\n')
    info('  h3 ping -c3 h4                  # BLOCKED  (h3 → h4)\n')
    info('  h4 iperf -s &                   # start iperf server on h4\n')
    info('  h1 iperf -c 10.0.0.4 -t 5      # allowed iperf\n')
    info('  h3 iperf -c 10.0.0.4 -t 5      # BLOCKED iperf\n')
    info('  sh cat firewall_log.txt         # view firewall log\n\n')

    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run()