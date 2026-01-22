from scapy.all import *

target = "172.16.1.1" # pfSense WAN Gateway
ports = range(1, 1025) 

print(f"Starting Full SYN Scan against {target}...")

for port in ports:
    syn = IP(dst=target)/TCP(dport=port, flags="S")
    resp = sr1(syn, timeout=0.1, verbose=False)

    if resp and resp.haslayer(TCP) and resp[TCP].flags == 0x12:
        print(f"Port {port} OPEN (Forwarded to DMZ)")
        send(IP(dst=target)/TCP(dport=port, flags="R"), verbose=False)