#!/bin/bash
# EE Experiment Runner
# Usage: sudo bash run_experiment.sh

PACKETS=500
TRIAL=1
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

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
ip netns exec nsA ping -c 2 10.0.0.2 || { echo "Network setup failed. Exiting."; exit 1; }

# ── Trial runner ───────────────────────────────────────────────────────────────
run() {
    local SCHEME=$1 CONDTYPE=$2 CONDRATE=$3

    echo "==> Trial $TRIAL | $SCHEME | $CONDTYPE | ${CONDRATE}%"

    pkill -f server.py 2>/dev/null
    pkill -f client.py 2>/dev/null
    sleep 2

    # Apply NetEM for loss conditions only
    if [ $CONDRATE -gt 0 ] && [ $CONDTYPE != "corrupt" ]; then
        if [ $CONDTYPE = "burst" ]; then
            ip netns exec nsA tc qdisc add dev vethA root netem loss ${CONDRATE}% 25%
        else
            ip netns exec nsA tc qdisc add dev vethA root netem loss ${CONDRATE}%
        fi
    fi

    ip netns exec nsB python3 "$SCRIPT_DIR/server.py" \
        --scheme "$SCHEME" --packets $PACKETS \
        --trial $TRIAL --losstype $CONDTYPE --lossrate $CONDRATE &
    SERVER_PID=$!
    sleep 2

    if [ $CONDTYPE = "corrupt" ]; then
        ip netns exec nsA python3 "$SCRIPT_DIR/client.py" \
            --scheme "$SCHEME" --packets $PACKETS --corrupt $CONDRATE
    else
        ip netns exec nsA python3 "$SCRIPT_DIR/client.py" \
            --scheme "$SCHEME" --packets $PACKETS
    fi

    wait $SERVER_PID

    [ $CONDRATE -gt 0 ] && [ $CONDTYPE != "corrupt" ] && \
        ip netns exec nsA tc qdisc del dev vethA root 2>/dev/null

    TRIAL=$((TRIAL + 1))
    sleep 5
}

# ── Main loop ──────────────────────────────────────────────────────────────────
# 6 schemes × 3 condition types × 4 rates × 5 trials = 360 trials
for SCHEME in "AES-GCM" "ChaCha20-Poly1305" "AES-CBC" "ChaCha20-MAC" "AES-CBC-NOAUTH" "ChaCha20-NOAUTH"; do
    for CONDTYPE in "standard" "burst" "corrupt"; do
        for CONDRATE in 0 10 20 30; do
            for i in 1 2 3 4 5; do
                run "$SCHEME" "$CONDTYPE" "$CONDRATE"
            done
        done
    done
done

echo "Done. Results in results.csv"
