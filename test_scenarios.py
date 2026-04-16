#!/usr/bin/env python3
"""
test_scenarios.py  —  Automated test runner for SDN Firewall
=============================================================
Run from INSIDE the Mininet CLI using:
    mininet> py exec(open('test_scenarios.py').read())

OR from a second terminal (with Mininet already running):
    sudo python3 test_scenarios.py
"""

import subprocess
import sys
import time

# ── Colours ─────────────────────────────────────────────────────────────────
GREEN  = '\033[92m'
RED    = '\033[91m'
YELLOW = '\033[93m'
BOLD   = '\033[1m'
RESET  = '\033[0m'

def hdr(msg):
    print(f'\n{BOLD}{YELLOW}{"="*55}{RESET}')
    print(f'{BOLD}{YELLOW}  {msg}{RESET}')
    print(f'{BOLD}{YELLOW}{"="*55}{RESET}')

def ok(msg):  print(f'  {GREEN}[PASS]{RESET} {msg}')
def fail(msg): print(f'  {RED}[FAIL]{RESET} {msg}')
def info(msg): print(f'  {YELLOW}[INFO]{RESET} {msg}')


def run_mn_cmd(cmd, timeout=15):
    """Run a command inside Mininet via subprocess (requires running net)."""
    result = subprocess.run(
        cmd, shell=True, capture_output=True, text=True, timeout=timeout
    )
    return result.returncode, result.stdout, result.stderr


# ── Scenario definitions ─────────────────────────────────────────────────────
SCENARIOS = [
    # (name, mininet_cmd, expect_success, description)
    (
        'Scenario 1a — h1 → h4 ICMP (should be ALLOWED)',
        'sudo mn --topo single,4 --test pingall',   # placeholder; run manually
        True,
        'Trusted host h1 can reach server h4'
    ),
    (
        'Scenario 1b — h2 → h4 ICMP (should be ALLOWED)',
        None,
        True,
        'Trusted host h2 can reach server h4'
    ),
    (
        'Scenario 2a — h3 → h4 ICMP (should be BLOCKED)',
        None,
        False,
        'Untrusted host h3 CANNOT reach server h4'
    ),
    (
        'Scenario 2b — h3 → h4 TCP iperf (should be BLOCKED)',
        None,
        False,
        'h3 TCP iperf to h4 is blocked by firewall rule R1'
    ),
]


def print_manual_test_guide():
    """Print the step-by-step manual test commands."""
    hdr('MANUAL TEST GUIDE — run these in Mininet CLI')

    print(f"""
{BOLD}SCENARIO 1: Allowed Traffic (h1 and h2 → h4){RESET}
─────────────────────────────────────────────
  # ICMP ping — expect 0% loss
  mininet> h1 ping -c 4 10.0.0.4
  mininet> h2 ping -c 4 10.0.0.4

  # TCP iperf — expect ~bandwidth reported
  mininet> h4 iperf -s &
  mininet> h1 iperf -c 10.0.0.4 -t 5
  mininet> h2 iperf -c 10.0.0.4 -t 5
  mininet> h4 kill %1          # stop iperf server

{BOLD}SCENARIO 2: Blocked Traffic (h3 → h4){RESET}
──────────────────────────────────────────
  # ICMP ping — expect 100% loss
  mininet> h3 ping -c 4 10.0.0.4

  # TCP iperf — expect connection refused / timeout
  mininet> h4 iperf -s &
  mininet> h3 iperf -c 10.0.0.4 -t 5
  mininet> h4 kill %1

{BOLD}FLOW TABLE INSPECTION{RESET}
──────────────────────
  mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s1

{BOLD}FIREWALL LOG{RESET}
────────────
  mininet> sh cat firewall_log.txt

{BOLD}WIRESHARK CAPTURE (on h3 interface){RESET}
──────────────────────────────────────
  mininet> h3 wireshark &
  (select h3-eth0 interface, filter: ip)
""")

    hdr('EXPECTED RESULTS SUMMARY')
    rows = [
        ('h1 → h4', 'ping',  'PASS (0% loss)'),
        ('h2 → h4', 'ping',  'PASS (0% loss)'),
        ('h1 → h2', 'ping',  'PASS (0% loss)'),
        ('h3 → h4', 'ping',  'FAIL (100% loss) ← firewall R1'),
        ('h3 → h4', 'iperf', 'FAIL (blocked)   ← firewall R1'),
        ('h1 → h4', 'iperf', 'PASS (bandwidth reported)'),
    ]
    print(f"  {'Source → Dest':<15} {'Tool':<8} {'Expected'}")
    print(f"  {'-'*50}")
    for src, tool, result in rows:
        colour = GREEN if 'PASS' in result else RED
        print(f"  {src:<15} {tool:<8} {colour}{result}{RESET}")


def check_log(log_file='firewall_log.txt'):
    hdr('FIREWALL LOG ANALYSIS')
    try:
        with open(log_file) as f:
            lines = f.readlines()
        blocked = [l for l in lines if 'BLOCKED' in l]
        if blocked:
            ok(f'Found {len(blocked)} blocked packet log entries:')
            for line in blocked[-10:]:      # show last 10
                print(f'    {line.rstrip()}')
        else:
            info('No blocked packets logged yet (run tests first).')
    except FileNotFoundError:
        info(f'{log_file} not found — start the controller first.')


if __name__ == '__main__':
    print_manual_test_guide()
    check_log()