#include <core.p4>
#include <v1model.p4>

// CONSTANTS
const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_IPV6 = 0x86DD;
const bit<8> PROTO_TCP = 6;
const bit<8> PROTO_UDP = 17;
const bit<32> FLOW_TABLE_SIZE = 65536;

// TYPE ALIASES
typedef bit<48> macAddr_t;
typedef bit<9> egressSpec_t;

// HEADERS
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header ipv6_t {
    bit<4> version;
    bit<8> trafficClass;
    bit<20> flowLabel;
    bit<16> payloadLen;
    bit<8> nextHeader;
    bit<8> hopLimit;
    bit<128> srcAddr;
    bit<128> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4> dataOffset;
    bit<3> res;
    bit<9> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

// Custom header to carry extracted features (appended to packet)
header features_t {
    bit<32> pkt_size;
    bit<48> iat;
    bit<32> flow_idx;
}

struct headers_t {
    ethernet_t ethernet;
    ipv4_t ipv4;
    ipv6_t ipv6;
    tcp_t tcp;
    udp_t udp;
    features_t features;
}

struct metadata_t {
    bit<48> current_timestamp;
    bit<48> last_timestamp;
    bit<48> iat;
    bit<32> pkt_size;
    bit<1> valid_l4;
    bit<32> flow_idx;
}

// REGISTERS
register<bit<48>>(1) reg_last_timestamp;
register<bit<32>>(FLOW_TABLE_SIZE) reg_flow_pkt_count;
register<bit<32>>(FLOW_TABLE_SIZE) reg_flow_byte_count;
register<bit<48>>(FLOW_TABLE_SIZE) reg_flow_first_ts;
register<bit<48>>(FLOW_TABLE_SIZE) reg_flow_last_ts;

// PARSER
parser MyParser(
    packet_in packet,
    out headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t standard_metadata)
{
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTO_TCP: parse_tcp;
            PROTO_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHeader) {
            PROTO_TCP: parse_tcp;
            PROTO_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}

// VERIFY CHECKSUM
control MyVerifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

// INGRESS
control MyIngress(
    inout headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t standard_metadata)
{
    action compute_packet_features() {
        meta.pkt_size = (bit<32>) standard_metadata.packet_length;
        meta.current_timestamp = standard_metadata.ingress_global_timestamp;
        reg_last_timestamp.read(meta.last_timestamp, 0);
        meta.iat = meta.current_timestamp - meta.last_timestamp;
        reg_last_timestamp.write(0, meta.current_timestamp);
    }

    action append_features_header() {
        hdr.features.setValid();
        hdr.features.pkt_size = meta.pkt_size;
        hdr.features.iat = meta.iat;
        hdr.features.flow_idx = meta.flow_idx;
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action forward(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action decrement_ttl_ipv4() {
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action decrement_hop_limit_ipv6() {
        hdr.ipv6.hopLimit = hdr.ipv6.hopLimit - 1;
    }

    table ipv4_lpm {
        key = { hdr.ipv4.dstAddr : lpm; }
        actions = { forward; drop; NoAction; }
        default_action = drop();
    }

    table ipv6_lpm {
        key = { hdr.ipv6.dstAddr : lpm; }
        actions = { forward; drop; NoAction; }
        default_action = drop();
    }


    action update_flow_counters() {
        bit<32> pkt_count;
        bit<32> byte_count;
        bit<48> first_ts;

        reg_flow_pkt_count.read(pkt_count, meta.flow_idx);
        reg_flow_byte_count.read(byte_count, meta.flow_idx);
        reg_flow_first_ts.read(first_ts, meta.flow_idx);

        reg_flow_pkt_count.write(meta.flow_idx, pkt_count + 1);
        reg_flow_byte_count.write(meta.flow_idx, byte_count + meta.pkt_size);

        if (first_ts == 0) {
            reg_flow_first_ts.write(meta.flow_idx, meta.current_timestamp);
        }
        reg_flow_last_ts.write(meta.flow_idx, meta.current_timestamp);
    }

    action update_flow_registers_ipv4() {
        hash(
            meta.flow_idx,
            HashAlgorithm.crc32,
            (bit<32>) 0,
            { hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr,
              hdr.tcp.isValid() ? hdr.tcp.srcPort : hdr.udp.srcPort,
              hdr.tcp.isValid() ? hdr.tcp.dstPort : hdr.udp.dstPort,
              hdr.ipv4.protocol },
            FLOW_TABLE_SIZE
        );
        update_flow_counters();
    }

    action update_flow_registers_ipv6() {
        hash(
            meta.flow_idx,
            HashAlgorithm.crc32,
            (bit<32>) 0,
            { hdr.ipv6.srcAddr,
              hdr.ipv6.dstAddr,
              hdr.tcp.isValid() ? hdr.tcp.srcPort : hdr.udp.srcPort,
              hdr.tcp.isValid() ? hdr.tcp.dstPort : hdr.udp.dstPort,
              hdr.ipv6.nextHeader },
            FLOW_TABLE_SIZE
        );
        update_flow_counters();
    }

    apply {
        compute_packet_features();

        if (hdr.ipv4.isValid()) {
            if (hdr.ipv4.ttl == 0) { drop(); return; }
            decrement_ttl_ipv4();
            ipv4_lpm.apply();
            if (hdr.tcp.isValid() || hdr.udp.isValid()) {
                update_flow_registers_ipv4();
                append_features_header();
            }
        } else if (hdr.ipv6.isValid()) {
            if (hdr.ipv6.hopLimit == 0) { drop(); return; }
            decrement_hop_limit_ipv6();
            ipv6_lpm.apply();
            if (hdr.tcp.isValid() || hdr.udp.isValid()) {
                update_flow_registers_ipv6();
                append_features_header();
            }
        }

        forward(1);
    }
}

control MyEgress(
    inout headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t standard_metadata)
{
    apply { }
}

control MyComputeChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv,
              hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags,
              hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol,
              hdr.ipv4.srcAddr, hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

control MyDeparser(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.features);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
