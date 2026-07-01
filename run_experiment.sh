#!/bin/bash
# EE Experiment Runner — runs all trials for one scheme at a time
# Usage: bash run_experiment.sh

PACKETS=500
TRIAL=1

ip netns del nsA 2>/dev/null
ip netns del nsB 2>/dev/null
ip link del vethA 2>/dev/null
 
ip netns add nsA
ip netns add nsB
ip link add vethA type veth peer name vethB
ip link set vethA netns nsA
ip link set vethB netns nsB
ip -n nsA addr add 10.0.0.1/24 dev vethA
ip -n nsB addr add 10.0.0.2/24 dev vethB
ip -n nsA link set vethA up
ip -n nsB link set vethB up
ip -n nsA link set lo up
ip -n nsB link set lo up
 
echo "Network ready. Testing"
#-----
ip netns exec nsA ping -c 2 10.0.0.2 || { echo "Network setup failed."; exit 1; }
run() {
    local SCHEME=$1 LOSSTYPE=$2 LOSSRATE=$3
    pkill -f server.py 2>/dev/null
    pkill -f client.py 2>/dev/null
    sleep 2
    # apply loss rule
    if [ $LOSSRATE -gt 0 ]; then
        if [ $LOSSTYPE = "burst" ]; then
            ip netns exec nsA tc qdisc add dev vethA root netem loss ${LOSSRATE}% 25%
        else
            ip netns exec nsA tc qdisc add dev vethA root netem loss ${LOSSRATE}%
        fi
    fi

    ip netns exec nsB python3 server.py --scheme "$SCHEME" --packets $PACKETS --trial $TRIAL --losstype $LOSSTYPE --lossrate $LOSSRATE &
    sleep 0.5
    ip netns exec nsA python3 client.py --scheme "$SCHEME" --packets $PACKETS
    wait

    [ $LOSSRATE -gt 0 ] && ip netns exec nsA tc qdisc del dev vethA root
    TRIAL=$((TRIAL + 1))
    sleep 5
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