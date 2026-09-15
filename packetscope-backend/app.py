from flask import Flask, request, jsonify
from flask_cors import CORS
from scapy.all import rdpcap, IP, IPv6, TCP, UDP, Ether, Raw
import os

app = Flask(__name__)
CORS(app)

# Holds the most recently uploaded/parsed packets in memory,
# so /api/packets/:id can look one up without re-parsing the file.
last_parsed_packets = []


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
            preview_bytes = payload[:50]

            # Count how many bytes look like normal readable text
            printable_count = sum(1 for b in preview_bytes if 32 <= b <= 126)
            is_mostly_text = printable_count / max(len(preview_bytes), 1) > 0.85

            if is_mostly_text:
                data["payload_preview"] = preview_bytes.decode("ascii", errors="replace")
                data["payload_type"] = "text"
            else:
                data["payload_preview"] = preview_bytes.hex()
                data["payload_type"] = "binary"
        except Exception:
            data["payload_preview"] = None
            data["payload_type"] = None

    data["length"] = len(packet)
    return data


def parse_uploaded_file():
    """Shared helper: validates upload, saves temp file, parses it, cleans up."""
    if "file" not in request.files:
        return None, (jsonify({"error": "No file uploaded"}), 400)

    file = request.files["file"]
    temp_path = "temp_upload.pcap"
    file.save(temp_path)

    packets = rdpcap(temp_path)
    all_parsed = [parse_packet(p) for p in packets]

    os.remove(temp_path)
    return all_parsed, None


@app.route("/ping")
def ping():
    return "pong"


@app.route("/api/upload", methods=["POST"])
def upload():
    global last_parsed_packets

    all_parsed, error = parse_uploaded_file()
    if error:
        return error

    # Add an "id" field to each packet so it can be looked up individually later
    for i, packet_data in enumerate(all_parsed):
        packet_data["id"] = i

    last_parsed_packets = all_parsed
    return jsonify(all_parsed)


@app.route("/api/packets/<int:packet_id>", methods=["GET"])
def get_packet(packet_id):
    if not last_parsed_packets:
        return jsonify({"error": "No packets loaded. Upload a file first via /api/upload"}), 404

    if packet_id < 0 or packet_id >= len(last_parsed_packets):
        return jsonify({"error": f"Packet id {packet_id} not found"}), 404

    return jsonify(last_parsed_packets[packet_id])


@app.route("/api/stats", methods=["POST"])
def stats():
    all_parsed, error = parse_uploaded_file()
    if error:
        return error

    counts = {}
    for p in all_parsed:
        proto = p.get("transport", p.get("protocol", "Other"))
        counts[proto] = counts.get(proto, 0) + 1

    return jsonify(counts)


if __name__ == "__main__":
    app.run(debug=True, port=5000)