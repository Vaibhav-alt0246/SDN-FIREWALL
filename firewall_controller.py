"""
SDN-Based Firewall Controller
Course: UE24CS252B - Computer Networks
Project: SDN-Based Firewall using Ryu + OpenFlow 1.3

Topology:
  h1 (10.0.0.1) - Trusted Host A
  h2 (10.0.0.2) - Trusted Host B
  h3 (10.0.0.3) - Untrusted Host (blocked from server)
  h4 (10.0.0.4) - Server

Firewall Rules:
  1. Block ALL traffic from h3 (10.0.0.3) to h4 (10.0.0.4)
  2. Block TCP port 5001 (iperf) from h3 to anywhere
  3. Allow all other traffic (h1 <-> h2, h1 <-> h4, h2 <-> h4)
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, icmp, ether_types
import logging
import datetime
import os

# ─── Firewall Rule Table ────────────────────────────────────────────────────
# Each rule is a dict. None = wildcard (match anything).
# Rules are evaluated top-to-bottom; first match wins.
FIREWALL_RULES = [
    # Rule 1: Block h3 → h4 (all protocols)
    {
        'id': 'R1',
        'src_ip':  '10.0.0.3',
        'dst_ip':  '10.0.0.4',
        'proto':   None,
        'dst_port': None,
        'action':  'BLOCK',
        'description': 'Block untrusted host h3 from reaching server h4'
    },
    # Rule 2: Block h3 → any on TCP port 5001 (iperf)
    {
        'id': 'R2',
        'src_ip':  '10.0.0.3',
        'dst_ip':  None,
        'proto':   'tcp',
        'dst_port': 5001,
        'action':  'BLOCK',
        'description': 'Block iperf (TCP 5001) traffic from h3'
    },
    # Rule 3: Allow everything else (implicit — no match = forward normally)
]

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, 'firewall_log.txt')


class SDNFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SDNFirewall, self).__init__(*args, **kwargs)

        # MAC → port learning table  {dpid: {mac: port}}
        self.mac_to_port = {}

        # Packet counters
        self.stats = {
            'total': 0,
            'blocked': 0,
            'forwarded': 0
        }

        # Set up file logger for blocked packets
        self.fwlog = logging.getLogger('firewall')
        self.fwlog.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s  %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        file_handler = logging.FileHandler(LOG_FILE)
        file_handler.setFormatter(formatter)
        self.fwlog.addHandler(file_handler)

        self.fwlog.info('=' * 60)
        self.fwlog.info('SDN Firewall Controller started')
        self.fwlog.info('=' * 60)

    # ─── Helpers ────────────────────────────────────────────────────────────

    def _print_rules(self):
        self.logger.info('[FIREWALL] Active rules:')
        for r in FIREWALL_RULES:
            self.logger.info('  [%s] %s → action=%s',
                             r['id'], r['description'], r['action'])

    def _check_firewall(self, src_ip, dst_ip, proto=None, dst_port=None):
        """
        Returns (matched_rule | None).
        Iterates rules in order; first matching BLOCK rule wins.
        """
        for rule in FIREWALL_RULES:
            if rule['action'] != 'BLOCK':
                continue
            if rule['src_ip']   and rule['src_ip']   != src_ip:
                continue
            if rule['dst_ip']   and rule['dst_ip']   != dst_ip:
                continue
            if rule['proto']    and rule['proto']     != proto:
                continue
            if rule['dst_port'] and rule['dst_port'] != dst_port:
                continue
            return rule          # matched
        return None              # no block rule matched → allow

    # ─── OpenFlow helpers ───────────────────────────────────────────────────

    def _add_flow(self, datapath, priority, match, actions,
                  idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod  = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )
        datapath.send_msg(mod)

    def _add_drop_flow(self, datapath, priority, match, idle_timeout=120):
        """Install a flow with empty instruction list → DROP."""
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=[],          # no actions = drop
            idle_timeout=idle_timeout,
            hard_timeout=0
        )
        datapath.send_msg(mod)
        self.logger.info('[FIREWALL] Drop flow installed on switch %s',
                         datapath.id)

    # ─── Event: switch connects ──────────────────────────────────────────────

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser

        # Table-miss entry: send unmatched packets to controller
        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, priority=0, match=match, actions=actions)
        self.logger.info('[FIREWALL] Switch %s connected — table-miss installed',
                         datapath.id)

    # ─── Event: packet arrives at controller ────────────────────────────────

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg      = ev.msg
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        in_port  = msg.match['in_port']
        dpid     = datapath.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # Ignore LLDP
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        src_mac = eth.src
        dst_mac = eth.dst
        self.stats['total'] += 1

        # ── MAC address learning ──────────────────────────────────────────
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

        # ── Firewall check (IP layer) ─────────────────────────────────────
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            src_ip   = ip_pkt.src
            dst_ip   = ip_pkt.dst
            proto    = None
            dst_port = None

            tcp_pkt = pkt.get_protocol(tcp.tcp)
            udp_pkt = pkt.get_protocol(udp.udp)

            if tcp_pkt:
                proto    = 'tcp'
                dst_port = tcp_pkt.dst_port
            elif udp_pkt:
                proto    = 'udp'
                dst_port = udp_pkt.dst_port

            rule = self._check_firewall(src_ip, dst_ip, proto, dst_port)

            if rule:
                # ── BLOCK ────────────────────────────────────────────────
                self.stats['blocked'] += 1
                log_entry = (
                    f"BLOCKED | rule={rule['id']} | "
                    f"{src_ip} -> {dst_ip} | "
                    f"proto={proto or 'ip'} | port={dst_port or '*'} | "
                    f"switch={dpid} in_port={in_port}"
                )
                self.logger.warning('[FIREWALL] %s', log_entry)
                self.fwlog.warning(log_entry)

                # Install a proactive drop flow so future packets
                # are dropped in the data-plane without hitting controller
                if proto == 'tcp':
                    drop_match = parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=src_ip,
                        ipv4_dst=dst_ip,
                        ip_proto=6,        # TCP
                        tcp_dst=dst_port
                    )
                elif proto == 'udp':
                    drop_match = parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=src_ip,
                        ipv4_dst=dst_ip,
                        ip_proto=17        # UDP
                    )
                else:
                    drop_match = parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=src_ip,
                        ipv4_dst=dst_ip
                    )

                self._add_drop_flow(datapath, priority=100,
                                    match=drop_match, idle_timeout=120)
                return   # do NOT forward this packet

        # ── ALLOW: normal learning-switch forwarding ──────────────────────
        self.stats['forwarded'] += 1

        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install a forward flow rule (only for unicast)
        if out_port != ofproto.OFPP_FLOOD:
            if ip_pkt:
                fwd_match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=ip_pkt.src,
                    ipv4_dst=ip_pkt.dst
                )
            else:
                fwd_match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)

            self._add_flow(datapath, priority=10,
                           match=fwd_match, actions=actions,
                           idle_timeout=60)

        # Send the current packet out
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)

    # ─── Periodic stats print (every 30 s via Ryu hub) ──────────────────────
    # Uncomment if you want live stats in the console:
    #
    # from ryu.lib import hub
    # def __init__(...):
    #     ...
    #     self.monitor_thread = hub.spawn(self._monitor)
    #
    # def _monitor(self):
    #     while True:
    #         self.logger.info('[STATS] total=%d blocked=%d forwarded=%d',
    #             self.stats['total'], self.stats['blocked'], self.stats['forwarded'])
    #         hub.sleep(30)