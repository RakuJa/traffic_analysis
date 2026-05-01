# Create two separate namespace pairs
# ns_replay: where tcpreplay runs (sends packets)
# ns_capture: where tcpdump runs (receives packets)
sudo ip netns add ns_replay
sudo ip netns add ns_capture

# Create veth pairs
# pair 1: (veth0 (host), veth0_inner (ns_replay)) - input to switch
# pair 2: (veth1 (host), veth1_inner (ns_capture)) - output from switch
sudo ip link add veth0 type veth peer name veth0_inner
sudo ip link add veth1 type veth peer name veth1_inner

sudo ip link set veth0_inner netns ns_replay
sudo ip link set veth1_inner netns ns_capture

sudo ip link set veth0 up
sudo ip link set veth1 up
sudo ip netns exec ns_replay  ip link set veth0_inner up
sudo ip netns exec ns_capture ip link set veth1_inner up

echo "Network namespaces ready :)"
