from scapy.all import *

target = "192.168.40.14" # Webserver's IP
ports = range(1, 1025)   # scanning 1024 ports

print(f"Starting VPN SYN Scan against {target}...")

for port in ports:
    syn = IP(dst=target)/TCP(dport=port, flags="S")
    resp = sr1(syn, timeout=0.1, verbose=False)

    if resp and resp.haslayer(TCP) and resp[TCP].flags == 18:
        print(f"Port {port} OPEN")
        send(IP(dst=target)/TCP(dport=port, flags="R"), verbose=False)