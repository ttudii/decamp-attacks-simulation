from scapy.all import *

subnet = "192.168.40.32/28"

print(f"Starting ARP Sweep on {subnet}...")

arp = ARP(pdst=subnet)
ether = Ether(dst="ff:ff:ff:ff:ff:ff")
packet = ether / arp

answered, _ = srp(packet, timeout=3, verbose=False)

print("\nIP Address\tMAC Address")
print("-" * 30)
for _, rcv in answered:
    print(f"{rcv.psrc}\t{rcv.hwsrc}")