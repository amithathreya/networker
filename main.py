import json
import logging
from collections import defaultdict
from datetime import datetime, timezone

from scapy.all import (
    ICMP,  # type: ignore
    IP,  # type: ignore
    TCP,  # type: ignore
    UDP,  # type: ignore
    Ether,  # type: ignore
    IPv6,  # type: ignore
    Raw,
    sniff,
)
from tumbling_window import TumblingWindow

OUTPUT_PACKETS_FILE = "data/packet/packet_info.json"

OUTPUT_FLOWS_FILE = "data/flow/flow_summaries.json"

PACKET_CAPTURE_LIMIT = 0


packets = []

flows = defaultdict(list)

tumbling = TumblingWindow()
# the flow key will be a tuple: (src IP, destination IP, src port, dst port, protocol)

# Protocol number to name mapping
PROTOCOL_MAP = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
}


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
    tumbling.add_packet(info, flow_key)


def calculate_flow_stats(pkts,flow_key):
    if not pkts:
        return None

    times = [p["timestamp_epoch"] for p in pkts]
    duration = max(times) - min(times) if len(times) > 1 else 0
    total_bytes = sum(p["length"] for p in pkts)
    anchor_ip = flow_key[0]
    protocol_num = flow_key[4]
    protocol_name = PROTOCOL_MAP.get(protocol_num, f"Unknown({protocol_num})")

    fwd_pkts = [p for p in pkts if p.get("src_ip") == anchor_ip]
    bwd_pkts = [p for p in pkts if p.get("src_ip") != anchor_ip]

    return {
        "protocol_name": protocol_name,
        "packet_count": len(pkts),
        "duration": duration,
        "total_bytes": total_bytes,
        "first_timestamp": min(times),
        "last_timestamp": max(times),
        "packets_fwd": len(fwd_pkts),
        "bytes_fwd": sum(p["length"] for p in fwd_pkts),
        "packets_bwd": len(bwd_pkts),
        "bytes_bwd": sum(p["length"] for p in bwd_pkts),
        "syn_count": sum(1 for p in pkts if "S" in p.get("flags_str", "")),
        "rst_count": sum(1 for p in pkts if "R" in p.get("flags_str", "")),
        "ack_count": sum(1 for p in pkts if "A" in p.get("flags_str", "")),
        "fin_count": sum(1 for p in pkts if "F" in p.get("flags_str", ""))  
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

        stats = calculate_flow_stats(pkts,flow_key=flow_key)
        print(f"Flow: {flow_key}")
        print(f"  Packets : {stats['packet_count']:3d}")  # type: ignore
        print(f"  Duration: {stats['duration']:6.2f} s")  # type: ignore
        print(f"  Bytes   : {stats['total_bytes']:6d}")  # type: ignore
        print(f"  First   : {stats['first_timestamp']:.2f}")  # type: ignore
        print("-" * 60)


def save_flow_summaries(filename=OUTPUT_FLOWS_FILE):
    flow_summaries = []
    for flow_key, pkts in flows.items():
        if not pkts:
            continue

        stats = calculate_flow_stats(pkts,flow_key=flow_key)
        summary = {"flow_key": flow_key, **stats}  # type: ignore
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
            print(f"Captured {counter['count']} packets...", end="\r")
            try:
                packet_handler(packet)
                counter["success"] += 1
            except Exception as e:
                print(f"\nError processing packet {counter['count']}: {e}")

        print("Starting packet capture...")
        sniff(iface="Realtek RTL8852BE WiFi 6 802.11ax PCIe Adapter", prn=packet_counter, store=False)

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

        # Dump tumbling windows JSON containing windows info and flow state info
        tumbling.dump_json()

    except KeyboardInterrupt:
        print("\nCapture interrupted by user")
    except Exception as e:
        print(f"Error during capture: {e}")
        
    
    # At the end of main.py
    with open("data/network_sequence.txt", "w") as f: 
        # Iterate through every window
        for idx in sorted(tumbling.windows.keys()):
            # Get all flow-token pairs for this 5-second slice
            flow_tokens = tumbling.get_window_token(idx)
            for entry in flow_tokens:
                f.write(entry + "\n")