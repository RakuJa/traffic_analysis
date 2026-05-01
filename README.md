# Network Traffic Analysis with Programmable Dataplanes

Analysis of real-world network traffic from the [MAWI Working Group](https://mawi.wide.ad.jp/mawi/) using two complementary approaches: python statistical analysis (Task 1) and network feature extraction with P4 (Task 2).

## Transparency: AI Usage

Claude Sonnet 4.6 has been utilized for:
1. Writing the `read_pcap_features` function, making the AI extract the logic from the one in the task1 and the new structure of the headers;
2. Documentation of the P4 language while writing the code (e.g. Q: "What is the name of the size field?");
3. Helper while debugging P4 code.
4. Increase velocity while porting from standard Python code to notebook `analysis.ipynb`

The verification process has been the following:
1. Never let AI "code" on the local machine: the code was extracted manually from the web interface, verifying it like a PR;
2. Each modification was requested as atomic as possible: avoid asking for a complete program and instead only request the minimum code possible (e.g. function/line);
3. Each time an AI fragment of code was added, complete testing of the interested script was carried out, avoiding multiple additions without testing the behavior;
4. Use of git versioning to quickly visualize modifications: in the final repository the commit history has been cleared to avoid exposing the PDF containing the instructions and personal information (e.g. mail)
## Environment

**Task 1** runs on any standard Linux machine with Python 3.14+ and [uv](https://docs.astral.sh/uv/).

**Task 2** requires the P4 tutorials [VM](https://github.com/jafingerhut/p4-guide/blob/master/bin/README-install-troubleshooting.md). All Task 2 commands below are run **inside the VM**, from the `analysis/` directory unless stated otherwise.

---

## Setup with notebook
To look at the results, having all the files required in the `data` folder, it's highly suggested to use the notebook.
```bash
export PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python && uv run jupyter lab analysis.ipynb
```

## Task 1 - Python traffic analysis

It is suggested to utilize the `analysis.ipynb` notebook for this task, since all the logic has been ported there and improved.

### Setup without notebook
```bash
cd programmable_dataplanes && uv run python task1.py
```

This reads the first 100,000 packets from `data/201302011400.dump` and produces 12 PDF plots (4 features * 3 protocol splits: ALL, TCP, UDP):

Plots are saved in the current working directory (`programmable_dataplanes/`).

---

## Task 2 - Network Feature Extraction using P4

The P4 program appends a 14-byte `features_t` header to every TCP/UDP packet as it transits the switch:

```
features_t { pkt_size[4 bytes] | iat[6 bytes] | flow_idx[4 bytes] }
```

Flow level features (packet count, byte count, first/last timestamp) are also tracked in P4 registers and reconstructed from the output PCAP.

### 1. Network setup

Creates two virtual Ethernet pairs and two network namespaces (`ns_replay` for traffic injection, `ns_capture` for output capture):

```bash
sudo bash setup.sh
```

### 2. Compile the P4 program

```bash
p4c --target bmv2 --arch v1model --p4runtime-files traffic_analysis.p4info.txt traffic_analysis.p4
```

### 3. Start the switch

Run in a dedicated terminal and keep it running:

```bash
sudo simple_switch_grpc --device-id 0 -i 0@veth0 -i 1@veth1 traffic_analysis.json -- --grpc-server-addr 0.0.0.0:9559
```

### 4. Push the pipeline config
```bash
cd programmable_dataplanes
uv run python task2.py --setup
```

### 5. Capture output and replay traffic

Open two terminals:

Terminal A, start capture first:
```bash
sudo ip netns exec ns_capture tcpdump -i veth1_inner -w output_with_features.pcap
```

Terminal B, replay traffic (after A started):
```bash
sudo ip netns exec ns_replay tcpreplay --multiplier=0.01 --limit=100000 -i veth0_inner programmable_dataplanes/data/201302011400.dump
```

After tcpreplay finishes, tcpdump can be stopped in Terminal A with `Ctrl+C`.

**Notes on replay speed:**
- `--multiplier=0.01` replays at 1% speed. bmv2 is a software switch and drops packets at higher rates.

### 6. Extract features and produce plots

It is highly suggested to copy out of the machine the `output_with_features.pcap` file and examine it through the notebook. Otherwise, for quick checks:

```bash
cd programmable_dataplanes && uv run python task2.py
```

This reads `output_with_features.pcap`, parses the `features_t` header and produces plot.