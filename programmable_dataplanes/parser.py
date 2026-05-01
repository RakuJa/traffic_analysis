import sys
from collections import defaultdict
from typing import Optional

from scapy.compat import raw
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Packet
from scapy.plist import PacketList

from structs.packet_data import PacketData, PacketIdentifier, PacketDataByProtocol


def parse_packet(pkt, idx) -> Optional[Packet]:
    try:
        raw_bytes = raw(Ether(raw(pkt)))
        ip_bytes = raw_bytes[14:]

        version = ip_bytes[0] >> 4

        if version == 4:
            return IP(ip_bytes)
        elif version == 6:
            return IPv6(ip_bytes)
        else:
            print(
                f"[WARN] Packet {idx}: unknown IP version ({version}), skipping",
                file=sys.stderr,
            )
            return None

    except Exception as e:
        print(f"[WARN] Packet {idx}: failed to parse ({e}), skipping", file=sys.stderr)
        return None


def parse_packets_into_packet_data(packets: PacketList) -> PacketDataByProtocol:
    sizes = {"udp": [], "tcp": [], "all": []}
    timestamps = {"udp": [], "tcp": [], "all": []}
    flows = {
        "udp": defaultdict(list),
        "tcp": defaultdict(list),
        "all": defaultdict(list),
    }
    skipped = 0
    for idx, pkt in enumerate(packets):
        ip_pkt = parse_packet(pkt, idx)
        if ip_pkt is None:
            skipped += 1
            continue
        else:
            ip_pkt: Packet
        sizes["all"].append(len(pkt))
        timestamps["all"].append(float(pkt.time))

        if not (pkt.haslayer("IP") or pkt.haslayer("IPv6")):
            continue

        protocol = ip_pkt.proto if ip_pkt.haslayer("IP") else ip_pkt.nh

        # Get ports if TCP/UDP
        if pkt.haslayer("TCP"):
            sizes["tcp"].append(len(pkt))
            timestamps["tcp"].append(float(pkt.time))
            source_port = pkt["TCP"].sport
            dest_port = pkt["TCP"].dport
            flow_key = PacketIdentifier(
                ip_pkt.src, ip_pkt.dst, source_port, dest_port, protocol
            )
            flows["tcp"][flow_key].append(pkt)
            flows["all"][flow_key].append(pkt)
        elif pkt.haslayer("UDP"):
            sizes["udp"].append(len(pkt))
            timestamps["udp"].append(float(pkt.time))
            source_port = pkt["UDP"].sport
            dest_port = pkt["UDP"].dport
            flow_key = PacketIdentifier(
                ip_pkt.src, ip_pkt.dst, source_port, dest_port, protocol
            )
            flows["udp"][flow_key].append(pkt)
            flows["all"][flow_key].append(pkt)

    return PacketDataByProtocol(
        udp_packet_data=PacketData(
            sizes=sizes["udp"],
            timestamps=timestamps["udp"],
            flows=flows["udp"],
        ),
        tcp_packet_data=PacketData(
            sizes=sizes["tcp"],
            timestamps=timestamps["tcp"],
            flows=flows["tcp"],
        ),
        all_packet_data=PacketData(
            sizes=sizes["all"],
            timestamps=timestamps["all"],
            flows=flows["all"],
        ),
    )


def flow_analysis(flows: dict[PacketIdentifier, list[Packet]]) -> tuple[list, list]:
    durations = []
    throughputs = []
    for flow_key, packets in flows.items():
        flow_timestamps = [float(p.time) for p in packets]
        total_bytes = sum(len(p) for p in packets)
        duration = max(flow_timestamps) - min(flow_timestamps)
        durations.append(duration)
        if duration > 0:
            bytes_per_sec = total_bytes / duration
            throughputs.append(bytes_per_sec)
    return durations, throughputs
