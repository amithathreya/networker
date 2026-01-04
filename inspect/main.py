import json
from collections import defaultdict
from datetime import datetime, timezone

OUTPUT_PACKETS_FILE = "data/packet/packet_info.json"
OUTPUT_FLOWS_FILE = "data/flow/flow_summaries.json"
PACKET_CAPTURE_LIMIT = 0

packets = []
flows = defaultdict(list)
# the flow key will be a tuple: (src IP, destination IP, src port, dst port, protocol)
"""
1 ICMP
2 IGMP
6 TCP
17 UDP
41 IPV6
47 GRE
50 ESP
51 AH
58 ICMPV6
89 OSPF
"""


def get_flow_key(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
    elif IPv6 in packet:
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst
        protocol = packet[IPv6].nh
    else:
        return None

    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    else:
        src_port = 0
        dst_port = 0
    if src_ip > dst_ip or (src_ip == dst_ip and src_port > dst_port):
        src_ip, dst_ip = dst_ip, src_ip
        src_port, dst_port = dst_port, src_port
        # swap ip and port to normalize flow key and maintain bidirection flow
    return (src_ip, dst_ip, src_port, dst_port, protocol)


def packet_handler(packet):
    info = {}
    info["timestamp_epoch"] = packet.time
    info["timestamp_utc"] = datetime.fromtimestamp(
        packet.time, tz=timezone.utc
    ).isoformat()
    info["timestamp_local"] = datetime.fromtimestamp(packet.time).isoformat()
    info["summary"] = packet.summary()
    info["length"] = len(packet)

    if Ether in packet:
        info["src_mac"] = packet[Ether].src
        info["dst_mac"] = packet[Ether].dst
        info["ether_type"] = packet[Ether].type

    if IP in packet:
        info["src_ip"] = packet[IP].src
        info["dst_ip"] = packet[IP].dst
        info["ip_version"] = packet[IP].version
        info["ttl"] = packet[IP].ttl
        info["protocol"] = packet[IP].proto
        info["ip_length"] = packet[IP].len
    elif IPv6 in packet:
        info["src_ip"] = packet[IPv6].src
        info["dst_ip"] = packet[IPv6].dst
        info["ip_version"] = packet[IPv6].version
        info["ttl"] = packet[IPv6].hlim
        info["protocol"] = packet[IPv6].nh

    if TCP in packet:
        info["src_port"] = packet[TCP].sport
        info["dst_port"] = packet[TCP].dport
        info["seq"] = packet[TCP].seq
        info["ack"] = packet[TCP].ack
        info["window"] = packet[TCP].window
        info["flags_str"] = str(packet[TCP].flags)
    elif UDP in packet:
        info["src_port"] = packet[UDP].sport
        info["dst_port"] = packet[UDP].dport
    elif ICMP in packet:
        info["icmp_type"] = packet[ICMP].type
        info["icmp_code"] = packet[ICMP].code

    if Raw in packet:
        try:
            info["payload_length"] = len(packet[Raw].load)
        except (IndexError, AttributeError):
            logging.warning("Failed to get payload length")
            info["payload_length"] = 0
    packets.append(info)
    flow_key = get_flow_key(packet)
    if flow_key:
        flows[flow_key].append(info)


def calculate_flow_stats(pkts):
    if not pkts:
        return None

    times = [p["timestamp_epoch"] for p in pkts]
    duration = max(times) - min(times) if len(times) > 1 else 0
    total_bytes = sum(p["length"] for p in pkts)

    return {
        "packet_count": len(pkts),
        "duration": duration,
        "total_bytes": total_bytes,
        "first_timestamp": min(times),
        "last_timestamp": max(times),
    }


def print_flow_summary():
    print("\n" + "=" * 70)
    print("          FLOW SUMMARY (after capture)")
    print("=" * 70)

    for flow_key, pkts in sorted(
        flows.items(), key=lambda x: min(p["timestamp_epoch"] for p in x[1])
    ):
        if not pkts:
            continue

        stats = calculate_flow_stats(pkts)
        print(f"Flow: {flow_key}")
        print(f"  Packets : {stats['packet_count']:3d}")
        print(f"  Duration: {stats['duration']:6.2f} s")
        print(f"  Bytes   : {stats['total_bytes']:6d}")
        print(f"  First   : {stats['first_timestamp']:.2f}")
        print("-" * 60)


def save_flow_summaries(filename=OUTPUT_FLOWS_FILE):
    flow_summaries = []
    for flow_key, pkts in flows.items():
        if not pkts:
            continue

        stats = calculate_flow_stats(pkts)
        summary = {"flow_key": flow_key, **stats}
        flow_summaries.append(summary)

    try:
        with open(filename, "w") as fs:
            json.dump(flow_summaries, fs, indent=4)
        print(f"Flow summaries saved to {filename}")
    except IOError as e:
        print(f"Error writing to {filename}: {e}")


if __name__ == "__main__":
    try:
        counter = {"count": 0, "success": 0}

        def packet_counter(packet):
            counter["count"] += 1
            if counter["count"] % 100 == 0:
                print(f"Captured {counter['count']} packets...", end="\r")
            try:
                packet_handler(packet)
                counter["success"] += 1
            except Exception as e:
                print(f"\nError processing packet {counter['count']}: {e}")

        print("Starting packet capture...")
        sniff(iface="eth0", prn=packet_counter, store=False)

        print(
            f"\nCapture complete. Total packets captured: {counter['count']}, Successfully processed: {counter['success']}"
        )

        print(
            f"\nCapture complete. Total packets captured: {counter['count']}, Successfully processed: {counter['success']}"
        )

        try:
            with open(OUTPUT_PACKETS_FILE, "w") as fs:
                json.dump(packets, fs, indent=4)
            print(f"Packet data saved to {OUTPUT_PACKETS_FILE}")
        except IOError as e:
            print(f"Error writing to {OUTPUT_PACKETS_FILE}: {e}")

        print_flow_summary()
        save_flow_summaries()

    except KeyboardInterrupt:
        print("\nCapture interrupted by user")
    except Exception as e:
        print(f"Error during capture: {e}")


"""
test comment
"""
