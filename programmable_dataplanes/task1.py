from scapy.plist import PacketList
from scapy.utils import rdpcap

from parser import parse_packets_into_packet_data, flow_analysis
from plotter import (
    plot_throughputs,
    plot_durations,
    plot_sizes,
    plot_inter_arrival_time,
)
from structs.packet_data import PacketData, PacketDataByProtocol

data_path: str = "data/201302011400.dump"
n_of_packets: int = 100_000  # 1_000_000


def plot(packet_data: PacketData, name: str):
    timestamps = packet_data.timestamps
    flows = packet_data.flows
    iats = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]

    durations, throughputs = flow_analysis(flows)
    plot_throughputs(throughputs, name=name)
    plot_durations(durations, name=name)
    plot_sizes(packet_data.sizes, name=name)
    plot_inter_arrival_time(iats, name=name)


if __name__ == "__main__":
    packets: PacketList = rdpcap(data_path, count=n_of_packets)
    data: PacketDataByProtocol = parse_packets_into_packet_data(packets)
    plot(data.udp_packet_data, "UDP")
    plot(data.tcp_packet_data, "TCP")
    plot(data.all_packet_data, "ALL")
