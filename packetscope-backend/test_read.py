from scapy.all import rdpcap, IP, IPv6, TCP, UDP, Ether, Raw
import json


def parse_packet(packet):
    data = {}

    if packet.haslayer(Ether):
        data["src_mac"] = packet[Ether].src
        data["dst_mac"] = packet[Ether].dst
        data["ethertype"] = hex(packet[Ether].type)

    if packet.haslayer(IP):
        data["src_ip"] = packet[IP].src
        data["dst_ip"] = packet[IP].dst
        data["protocol"] = "IPv4"
        data["ttl"] = packet[IP].ttl
        data["protocol_number"] = packet[IP].proto
    elif packet.haslayer(IPv6):
        data["src_ip"] = packet[IPv6].src
        data["dst_ip"] = packet[IPv6].dst
        data["protocol"] = "IPv6"

    if packet.haslayer(TCP):
        data["src_port"] = packet[TCP].sport
        data["dst_port"] = packet[TCP].dport
        data["transport"] = "TCP"
        data["tcp_flags"] = str(packet[TCP].flags)
        data["seq"] = packet[TCP].seq
        data["ack"] = packet[TCP].ack
    elif packet.haslayer(UDP):
        data["src_port"] = packet[UDP].sport
        data["dst_port"] = packet[UDP].dport
        data["transport"] = "UDP"

    if packet.haslayer(Raw):
        try:
            payload = bytes(packet[Raw].load)
            preview = payload[:50].decode("utf-8", errors="replace")
            data["payload_preview"] = preview
        except Exception:
            data["payload_preview"] = None

    data["length"] = len(packet)
    return data


# Load the pcap file
packets = rdpcap("sample1.pcapng")
print(f"Total packets: {len(packets)}\n")

# Parse every packet in the file
all_parsed = []
for packet in packets:
    parsed = parse_packet(packet)
    all_parsed.append(parsed)

# Convert the whole list to JSON
json_output = json.dumps(all_parsed, indent=2)

# Print just the first 500 characters so it doesn't flood your terminal
print(json_output[:500])

# Save the full thing to a file so you can inspect it properly
with open("output.json", "w") as f:
    f.write(json_output)

print(f"\n\nSaved {len(all_parsed)} packets to output.json")