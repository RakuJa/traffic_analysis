import grpc
import queue
import struct
import threading
import time
import numpy as np
from p4.v1 import p4runtime_pb2, p4runtime_pb2_grpc
from p4.config.v1 import p4info_pb2
from google.protobuf import text_format
from scapy.utils import rdpcap

from plotter import (
    plot_durations,
    plot_throughputs,
    plot_sizes,
    plot_inter_arrival_time,
)


def _open_mastership_stream(stub, device_id):
    q = queue.SimpleQueue()

    def req_gen():
        req = p4runtime_pb2.StreamMessageRequest()
        req.arbitration.device_id = device_id
        req.arbitration.election_id.low = 1
        yield req
        q.get()

    stream = stub.StreamChannel(req_gen())
    threading.Thread(target=lambda: [_ for _ in stream], daemon=True).start()
    time.sleep(0.2)
    return lambda: q.put(None)


def push_pipeline_config(
    p4info_path: str = "../traffic_analysis.p4info.txt",
    json_path: str = "../traffic_analysis.json",
    grpc_addr: str = "127.0.0.1:9559",
    device_id: int = 0,
):
    channel = grpc.insecure_channel(grpc_addr)
    stub = p4runtime_pb2_grpc.P4RuntimeStub(channel)

    stop = _open_mastership_stream(stub, device_id)

    p4info_msg = p4info_pb2.P4Info()
    with open(p4info_path, "r") as f:
        text_format.Merge(f.read(), p4info_msg)
    with open(json_path, "rb") as f:
        json_bytes = f.read()

    req = p4runtime_pb2.SetForwardingPipelineConfigRequest()
    req.device_id = device_id
    req.election_id.low = 1
    req.action = p4runtime_pb2.SetForwardingPipelineConfigRequest.VERIFY_AND_COMMIT
    req.config.p4info.CopyFrom(p4info_msg)
    req.config.p4_device_config = json_bytes
    stub.SetForwardingPipelineConfig(req)

    stop()
    channel.close()
    print("Pipeline config pushed successfully.")


_ETH_SIZE = 14
_IPV4_SIZE = 20
_IPV6_SIZE = 40
_TCP_SIZE = 20
_UDP_SIZE = 8
_FEAT_SIZE = 14  # pkt_size[4] + iat[6] + flow_idx[4]
_ETHERTYPE_IPV4 = 0x0800
_ETHERTYPE_IPV6 = 0x86DD
_PROTO_TCP = 6
_PROTO_UDP = 17


def _feat_offset(raw: bytes):
    if len(raw) < _ETH_SIZE + 2:
        return None
    ethertype = struct.unpack_from(">H", raw, 12)[0]
    if ethertype == _ETHERTYPE_IPV4:
        if len(raw) <= _ETH_SIZE + 9:
            return None
        proto = raw[_ETH_SIZE + 9]
        if proto == _PROTO_TCP:
            return _ETH_SIZE + _IPV4_SIZE + _TCP_SIZE
        if proto == _PROTO_UDP:
            return _ETH_SIZE + _IPV4_SIZE + _UDP_SIZE
    elif ethertype == _ETHERTYPE_IPV6:
        if len(raw) <= _ETH_SIZE + 6:
            return None
        nh = raw[_ETH_SIZE + 6]
        if nh == _PROTO_TCP:
            return _ETH_SIZE + _IPV6_SIZE + _TCP_SIZE
        if nh == _PROTO_UDP:
            return _ETH_SIZE + _IPV6_SIZE + _UDP_SIZE
    return None


def read_pcap_features(pcap_path: str):
    packets = rdpcap(pcap_path)
    sizes = []
    iats = []
    flows = {}

    for pkt in packets:
        raw = bytes(pkt)
        offset = _feat_offset(raw)
        if offset is None or len(raw) < offset + _FEAT_SIZE:
            continue

        pkt_size = struct.unpack_from(">I", raw, offset)[0]
        iat_us = int.from_bytes(raw[offset + 4 : offset + 10], byteorder="big")
        flow_idx = struct.unpack_from(">I", raw, offset + 10)[0]
        ts = float(pkt.time)

        sizes.append(pkt_size)
        iats.append(iat_us / 1_000_000)

        if flow_idx not in flows:
            flows[flow_idx] = {
                "pkt_count": 0,
                "byte_count": 0,
                "first_ts": ts,
                "last_ts": ts,
            }
        f = flows[flow_idx]
        f["pkt_count"] += 1
        f["byte_count"] += pkt_size
        if ts < f["first_ts"]:
            f["first_ts"] = ts
        if ts > f["last_ts"]:
            f["last_ts"] = ts

    return sizes, iats, flows


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--setup",
        action="store_true",
        help="Push pipeline config to the switch (run once before traffic replay)",
    )
    args = ap.parse_args()

    if args.setup:
        push_pipeline_config()
        exit()

    sizes, iats, flows = read_pcap_features("data/output_with_features.pcap")

    durations = []
    throughputs = []
    for fl in flows.values():
        duration = fl["last_ts"] - fl["first_ts"]
        if duration <= 0:
            continue
        durations.append(duration)
        throughputs.append(fl["byte_count"] / duration)

    print(f"PCAP packets with features: {len(sizes)}")
    print(f"Active flows: {len(flows)}")
    print(f"Mean duration: {np.mean(durations):.3f} s")
    print(f"Mean throughput: {np.mean(throughputs):.1f} bytes/s")

    plot_sizes(sizes, "p4")
    plot_inter_arrival_time(iats, "p4")
    plot_durations(durations, "p4")
    plot_throughputs(throughputs, "p4")
