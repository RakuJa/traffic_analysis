from dataclasses import dataclass

from scapy.packet import Packet


@dataclass(frozen=True)
class PacketIdentifier:
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str


@dataclass
class PacketData:
    sizes: list[int]
    timestamps: list[int]
    flows: dict[PacketIdentifier, list[Packet]]


@dataclass
class PacketDataByProtocol:
    udp_packet_data: PacketData
    tcp_packet_data: PacketData
    all_packet_data: PacketData
