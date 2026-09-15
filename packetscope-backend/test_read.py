from scapy.all import rdpcap, ICMP, IP

packets = rdpcap("sample3.pcapng")
print(f"Total packets: {len(packets)}\n")

icmp_count = 0
for packet in packets:
    if packet.haslayer(ICMP):
        icmp_count += 1
        print(packet.summary())

print(f"\nTotal ICMP packets found: {icmp_count}")