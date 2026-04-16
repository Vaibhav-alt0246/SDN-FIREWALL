# SDN-Based Firewall using Mininet + Ryu

**Course:** UE24CS252B — Computer Networks  
**Project:** SDN-Based Firewall (Project #2)

---

## Problem Statement

Implement a Software-Defined Networking (SDN) based firewall using Mininet and the Ryu OpenFlow controller. The controller intercepts packets via `packet_in` events, evaluates them against a rule table (matching on source IP, destination IP, protocol, and port), and either installs a **drop flow** (blocked) or a **forward flow** (allowed) on the switch. Blocked packets are logged to a file for audit purposes.

---

## Topology

```
  h1  10.0.0.1  (Trusted Host A)  ─┐
  h2  10.0.0.2  (Trusted Host B)  ─┤── s1 (OVS) ──── Ryu Controller
  h3  10.0.0.3  (Untrusted Host)  ─┤               (127.0.0.1:6633)
  h4  10.0.0.4  (Server)          ─┘
```

---

## Firewall Rules

| Rule | Source IP | Dest IP   | Protocol | Port | Action |
|------|-----------|-----------|----------|------|--------|
| R1   | 10.0.0.3  | 10.0.0.4  | any      | any  | **BLOCK** |
| R2   | 10.0.0.3  | any       | TCP      | 5001 | **BLOCK** |
| —    | any       | any       | any      | any  | ALLOW  |

---

## Setup & Execution

### Prerequisites

```bash
# 1. Install Mininet
sudo apt update && sudo apt install mininet -y

# 2. Set up Python 3.10 venv for Ryu (Python 3.12 is incompatible)
sudo apt update && sudo apt install mininet -y
sudo add-apt-repository ppa:deadsnakes/ppa -y
sudo apt install python3.9 python3.9-venv -y
python3.9 -m venv ryu_venv_39
source ryu_venv_39/bin/activate
pip install "setuptools<58.0.0"
pip install ryu eventlet==0.30.2
```

### Step 1 — Start the Ryu controller

Open **Terminal 1**:

```bash
source ryu_venv_39/bin/activate
ryu-manager --observe-links firewall_controller.py
```

You should see:
```
[FIREWALL] Controller started — log → firewall_log.txt
[FIREWALL] Active rules:
  [R1] Block untrusted host h3 from reaching server h4 → action=BLOCK
  [R2] Block iperf (TCP 5001) traffic from h3 → action=BLOCK
```

### Step 2 — Start the Mininet topology

Open **Terminal 2**:

```bash
sudo python3 topology.py
```

This starts Mininet, attaches to the Ryu controller, and drops you into the Mininet CLI.

---

## Test Scenarios

### Scenario 1 — Allowed Traffic

```bash
# ICMP ping (expect 0% loss)
mininet> h1 ping -c 4 10.0.0.4
mininet> h2 ping -c 4 10.0.0.4

# iperf throughput (expect bandwidth reported)
mininet> h4 iperf -s &
mininet> h1 iperf -c 10.0.0.4 -t 5
```

### Scenario 2 — Blocked Traffic

```bash
# ICMP ping from untrusted host (expect 100% loss)
mininet> h3 ping -c 4 10.0.0.4

# iperf from untrusted host (expect connection timeout)
mininet> h4 iperf -s &
mininet> h3 iperf -c 10.0.0.4 -t 5
```

---

## Expected Output

| Test | Expected Result |
|------|----------------|
| `h1 ping h4` | 0% packet loss |
| `h2 ping h4` | 0% packet loss |
| `h1 ping h2` | 0% packet loss |
| `h3 ping h4` | **100% packet loss** (blocked by R1) |
| `h3 iperf → h4` | **Timeout / no connection** (blocked by R1) |
| `h1 iperf → h4` | Bandwidth reported (allowed) |

---

## Inspecting Flow Tables & Logs

```bash
# View installed OpenFlow rules on the switch
mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s1

# View firewall block log
mininet> sh cat firewall_log.txt

# Cleanup Mininet state
sudo mn -c
```

---

## Proof of Execution

Screenshots and logs to include in submission:
1. `ovs-ofctl dump-flows s1` output showing drop rules (priority=100)
2. `firewall_log.txt` showing BLOCKED entries for h3 → h4 traffic
3. `h3 ping h4` showing 100% packet loss
4. `h1 ping h4` showing 0% packet loss
5. Wireshark capture on h3-eth0 (optional but recommended)

---

## References

1. Ryu SDN Framework — https://ryu.readthedocs.io/  
2. Mininet Walkthrough — https://mininet.org/walkthrough/  
3. OpenFlow 1.3 Specification — https://opennetworking.org/  
4. OVS OpenFlow Tutorial — https://github.com/openvswitch/ovs/blob/main/Documentation/tutorials/openflow-tutorial.rst

## SCREENSHOTS

/Users/vaby/Desktop/Screenshot 2026-04-16 at 8.06.34 PM.png 
/Users/vaby/Desktop/Screenshot 2026-04-16 at 8.06.46 PM.png 
/Users/vaby/Desktop/Screenshot 2026-04-16 at 8.07.54 PM.png