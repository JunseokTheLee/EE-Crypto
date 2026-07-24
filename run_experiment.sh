#!/bin/bash
# EE Cascade Length Experiment
# Usage: sudo bash run_experiment.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TRIAL=1

trap 'pkill -f server.py 2>/dev/null; pkill -f client.py 2>/dev/null; ip netns exec nsA tc qdisc del dev vethA root 2>/dev/null; exit 0' EXIT

# ── Network setup ──────────────────────────────────────────────────────────────
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

echo "Network ready. Testing connectivity..."
ip netns exec nsA ping -c 2 10.0.0.2 || { echo "Network setup failed."; exit 1; }

# ── Trial runner ───────────────────────────────────────────────────────────────
run() {
    local SCHEME=$1 LOSSTYPE=$2 LOSSRATE=$3

    echo "==> Trial $TRIAL | $SCHEME | $LOSSTYPE | ${LOSSRATE}%"

    pkill -f server.py 2>/dev/null
    pkill -f client.py 2>/dev/null
    sleep 2

    if [ $LOSSRATE -gt 0 ]; then
        if [ $LOSSTYPE = "burst" ]; then
            ip netns exec nsA tc qdisc add dev vethA root netem loss ${LOSSRATE}% 25%
        else
            ip netns exec nsA tc qdisc add dev vethA root netem loss ${LOSSRATE}%
        fi
    fi

    ip netns exec nsB python3 "$SCRIPT_DIR/server.py" \
        --scheme "$SCHEME" --trial $TRIAL \
        --losstype $LOSSTYPE --lossrate $LOSSRATE &
    SERVER_PID=$!
    sleep 2

    ip netns exec nsA python3 "$SCRIPT_DIR/client.py" \
        --scheme "$SCHEME"

    wait $SERVER_PID

    [ $LOSSRATE -gt 0 ] && ip netns exec nsA tc qdisc del dev vethA root 2>/dev/null

    TRIAL=$((TRIAL + 1))
    sleep 5
}

# ── Main loop ──────────────────────────────────────────────────────────────────
# 3 schemes × 2 loss types × 4 rates × 5 trials = 120 trials (~32 minutes)
for SCHEME in "AES-GCM" "AES-CBC" "AES-CBC-NOAUTH"; do
    for LOSSTYPE in "standard" "burst"; do
        for LOSSRATE in 0 10 20 30; do
            for i in 1 2 3 4 5; do
                run "$SCHEME" "$LOSSTYPE" "$LOSSRATE"
            done
        done
    done
done

echo "Done. Results in results_summary.csv and results_packets.csv"
