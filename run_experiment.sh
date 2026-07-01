#!/bin/bash
# EE Experiment Runner — runs all trials for one scheme at a time
# Usage: sudo bash run_experiment.sh

PACKETS=500
TRIAL=1

sudo ip netns del nsA 2>/dev/null
sudo ip netns del nsB 2>/dev/null
sudo ip link del vethA 2>/dev/null
 
sudo ip netns add nsA
sudo ip netns add nsB
sudo ip link add vethA type veth peer name vethB
sudo ip link set vethA netns nsA
sudo ip link set vethB netns nsB
sudo ip -n nsA addr add 10.0.0.1/24 dev vethA
sudo ip -n nsB addr add 10.0.0.2/24 dev vethB
sudo ip -n nsA link set vethA up
sudo ip -n nsB link set vethB up
sudo ip -n nsA link set lo up
sudo ip -n nsB link set lo up
 
echo "Network ready. Testing"
#-----
sudo ip netns exec nsA ping -c 2 10.0.0.2 || { echo "Network setup failed."; exit 1; }
run() {
    local SCHEME=$1 LOSSTYPE=$2 LOSSRATE=$3

    # apply loss rule
    if [ $LOSSRATE -gt 0 ]; then
        if [ $LOSSTYPE = "burst" ]; then
            sudo ip netns exec nsA tc qdisc add dev vethA root netem loss ${LOSSRATE}% 25%
        else
            sudo ip netns exec nsA tc qdisc add dev vethA root netem loss ${LOSSRATE}%
        fi
    fi

    sudo ip netns exec nsB python3 server.py --scheme "$SCHEME" --packets $PACKETS --trial $TRIAL --losstype $LOSSTYPE --lossrate $LOSSRATE &
    sleep 0.5
    sudo ip netns exec nsA python3 client.py --scheme "$SCHEME" --packets $PACKETS
    wait

    [ $LOSSRATE -gt 0 ] && sudo ip netns exec nsA tc qdisc del dev vethA root
    TRIAL=$((TRIAL + 1))
    sleep 10
}

for SCHEME in "AES-GCM" "ChaCha20-Poly1305" "AES-CBC" "ChaCha20-MAC"; do
    for LOSSTYPE in "standard" "burst"; do
        for LOSSRATE in 0 10 20 30; do
            for i in 1 2 3 4 5; do
                run "$SCHEME" "$LOSSTYPE" "$LOSSRATE"
            done
        done
    done
done

echo "Done. Results in results.csv"