"""
server.py — Cascade Length EE Experiment Receiver
Logs individual packet outcomes to a per-trial packet log.
Cascade lengths are computed from the sequence of outcomes.
"""

import socket, struct, time, csv, os, argparse
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hmac, hashes
from cryptography.hazmat.backends import default_backend

AES_KEY  = bytes.fromhex("00" * 32)
HMAC_KEY = bytes.fromhex("22" * 32)

SERVER_IP    = "10.0.0.2"
SERVER_PORT  = 9999
BUFFER_SIZE  = 65535
SUMMARY_CSV  = "results_summary.csv"
PACKET_CSV   = "results_packets.csv"
CHUNK_SIZE   = 256
NUM_PACKETS  = 500

STREAM_DATA  = bytes([i % 256 for i in range(NUM_PACKETS * CHUNK_SIZE)])

HEADER_FMT  = "!IBBHxx"
HEADER_SIZE = struct.calcsize(HEADER_FMT)

SCHEME_IDS = {
    "AES-GCM":        0,
    "AES-CBC":        1,
    "AES-CBC-NOAUTH": 2,
}

# ── Outcome codes (written to per-packet CSV) ──────────────────────────────────
OK             = "OK"           # decrypted correctly, plaintext matches
AUTH_FAIL      = "AUTH_FAIL"    # exception thrown — authenticated schemes
SILENT_CORRUPT = "SILENT"       # decrypted without error but wrong plaintext
DROPPED        = "DROPPED"      # never arrived

# ── Stateful decryptors ────────────────────────────────────────────────────────

class DecryptAESGCM:
    def __init__(self, first_nonce):
        self.gcm = AESGCM(AES_KEY)

    def decrypt(self, nonce, enc, seq):
        return self.gcm.decrypt(nonce, enc, None)


class DecryptAESCBC:
    """
    Tracks expected_next_iv across packets.
    After decrypting packet N, expected_next_iv = last 16 bytes of packet N's ciphertext.
    If packet N is dropped, expected_next_iv is never updated, so packet N+1's IV
    won't match — raises ValueError, logged as AUTH_FAIL.
    """
    def __init__(self, first_nonce):
        self.expected_next_iv = None   # unknown until first packet processed

    def decrypt(self, nonce, body, seq):
        mac_received = body[-32:]
        ciphertext   = body[:-32]
        # Verify HMAC over seq_num + IV + ciphertext
        h = hmac.HMAC(HMAC_KEY, hashes.SHA256(), backend=default_backend())
        h.update(seq.to_bytes(4, "big") + nonce + ciphertext)
        h.verify(mac_received)   # raises InvalidSignature if packet tampered
        # Check IV continuity — only once we've seen a previous packet
        if self.expected_next_iv is not None and nonce != self.expected_next_iv:
            raise ValueError(
                f"IV mismatch at seq={seq}: stream state broken by prior packet loss"
            )
        decryptor = Cipher(
            algorithms.AES(AES_KEY), modes.CBC(nonce),
            backend=default_backend()
        ).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        pad_len = padded[-1]
        if pad_len < 1 or pad_len > 16:
            raise ValueError(f"Bad padding: {pad_len}")
        plaintext = padded[:-pad_len]
        self.expected_next_iv = ciphertext[-16:]   # update expected IV for next packet
        return plaintext


class DecryptAESCBCNoAuth:
    """
    AES-CBC with no MAC — cascade failures are completely silent.
    The server tracks its own IV state independently of the packet header.
    When a packet is dropped, self.expected_iv falls out of sync with what
    the client used — decryption proceeds with the wrong IV, producing
    garbage plaintext that is caught as SILENT_CORRUPT by stream comparison.
    No exception is raised — the receiver has no way to know it went wrong.
    """
    def __init__(self, first_nonce):
        self.expected_iv = None   # set after first packet

    def decrypt(self, nonce, ciphertext, seq):
        # Use our tracked IV state, not the one from the packet header.
        # If a packet was dropped, self.expected_iv is wrong — silent failure.
        iv_to_use = self.expected_iv if self.expected_iv is not None else nonce
        decryptor = Cipher(
            algorithms.AES(AES_KEY), modes.CBC(iv_to_use),
            backend=default_backend()
        ).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        # Update expected IV from the ciphertext we just processed
        self.expected_iv = ciphertext[-16:]
        # Strip padding if valid, otherwise return raw bytes
        pad_len = padded[-1]
        if 1 <= pad_len <= 16:
            return padded[:-pad_len]
        return padded   # garbage — caught as SILENT_CORRUPT by stream comparison


def make_decryptor(scheme_id, first_nonce):
    if scheme_id == 0: return DecryptAESGCM(first_nonce)
    if scheme_id == 1: return DecryptAESCBC(first_nonce)
    if scheme_id == 2: return DecryptAESCBCNoAuth(first_nonce)

# ── CSV helpers ────────────────────────────────────────────────────────────────

SUMMARY_FIELDS = [
    "trial_id","scheme","loss_type","loss_rate_pct",
    "packets_sent","packets_received","packets_dropped",
    "auth_failures","silent_corruptions","stream_breaks",
    "cascade_count",           # number of distinct cascade events
    "mean_cascade_length",     # average length of a cascade run
    "max_cascade_length",      # longest cascade observed
    "loss_amplification",      # (failures+silent) / dropped
    "effective_throughput_kbps",
    "trial_duration_s","timestamp"
]

PACKET_FIELDS = [
    "trial_id","scheme","loss_type","loss_rate_pct","seq","outcome"
]

def init_csvs():
    if not os.path.exists(SUMMARY_CSV):
        with open(SUMMARY_CSV, "w", newline="") as f:
            csv.writer(f).writerow(SUMMARY_FIELDS)
    if not os.path.exists(PACKET_CSV):
        with open(PACKET_CSV, "w", newline="") as f:
            csv.writer(f).writerow(PACKET_FIELDS)

def write_summary(row):
    with open(SUMMARY_CSV, "a", newline="") as f:
        csv.DictWriter(f, fieldnames=SUMMARY_FIELDS).writerow(row)

def write_packet_log(rows):
    with open(PACKET_CSV, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=PACKET_FIELDS)
        for r in rows:
            w.writerow(r)

# ── Cascade analysis ───────────────────────────────────────────────────────────

def analyse_cascades(outcomes):
    """
    Given a list of (seq, outcome) tuples in arrival order,
    find consecutive runs of non-OK outcomes and measure their lengths.
    Returns: cascade_count, mean_length, max_length
    """
    cascade_lengths = []
    current_run = 0

    for seq, outcome in outcomes:
        if outcome != OK:
            current_run += 1
        else:
            if current_run > 0:
                cascade_lengths.append(current_run)
                current_run = 0

    if current_run > 0:
        cascade_lengths.append(current_run)

    if not cascade_lengths:
        return 0, 0.0, 0

    return (
        len(cascade_lengths),
        sum(cascade_lengths) / len(cascade_lengths),
        max(cascade_lengths)
    )

# ── Main server loop ───────────────────────────────────────────────────────────

def run_server(scheme, trial_id, loss_type, loss_rate):
    scheme_id = SCHEME_IDS[scheme]
    is_unauth = scheme_id == 2
    init_csvs()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((SERVER_IP, SERVER_PORT))
    sock.settimeout(5.0)

    print(f"[SERVER] {scheme} | trial={trial_id} | {loss_type} {loss_rate}%")
    print(f"[SERVER] Listening on {SERVER_IP}:{SERVER_PORT} ...")

    # Track per-packet outcomes
    packet_outcomes = {}   # seq -> outcome
    decryptor       = None
    bytes_decrypted = 0
    start_time = end_time = None
    seen_seqs   = set()
    last_seen_seq = -1     # tracks highest seq seen for gap detection

    while True:
        try:
            data, _ = sock.recvfrom(BUFFER_SIZE)
        except socket.timeout:
            print("[SERVER] Timeout.")
            break

        if start_time is None:
            start_time = time.perf_counter()
        end_time = time.perf_counter()

        if data == b"DONE":
            print("[SERVER] DONE received.")
            break

        if len(data) < HEADER_SIZE:
            continue

        seq_num, recv_id, nonce_len, chunk_size = struct.unpack(
            HEADER_FMT, data[:HEADER_SIZE]
        )

        if recv_id != scheme_id:
            continue
        if seq_num in seen_seqs:
            continue
        seen_seqs.add(seq_num)

        body  = data[HEADER_SIZE:]
        nonce = body[:nonce_len]
        enc   = body[nonce_len:]

        if decryptor is None:
            decryptor = make_decryptor(scheme_id, nonce)

        # Mark any skipped sequence numbers as DROPPED before processing this one
        for missing in range(last_seen_seq + 1, seq_num):
            packet_outcomes[missing] = DROPPED
        last_seen_seq = max(last_seen_seq, seq_num)

        try:
            plaintext = decryptor.decrypt(nonce, enc, seq_num)
            bytes_decrypted += len(plaintext)

            expected = STREAM_DATA[seq_num * CHUNK_SIZE:(seq_num + 1) * CHUNK_SIZE]
            if plaintext == expected:
                packet_outcomes[seq_num] = OK
            else:
                # Decrypted without error but wrong data — stream state broken
                packet_outcomes[seq_num] = SILENT_CORRUPT
                print(f"  seq={seq_num:04d}  SILENT CORRUPTION")

        except Exception as e:
            packet_outcomes[seq_num] = AUTH_FAIL
            print(f"  seq={seq_num:04d}  AUTH FAIL ({type(e).__name__})")

        if len(seen_seqs) >= NUM_PACKETS:
            print("[SERVER] All packets processed.")
            break

    sock.close()

    # Fill in any trailing dropped packets
    for missing in range(last_seen_seq + 1, NUM_PACKETS):
        packet_outcomes[missing] = DROPPED

    # ── Compute summary metrics ────────────────────────────────────────────────
    outcomes_list = [(s, packet_outcomes.get(s, DROPPED)) for s in range(NUM_PACKETS)]

    packets_received  = sum(1 for _, o in outcomes_list if o != DROPPED)
    packets_dropped   = NUM_PACKETS - packets_received
    auth_failures     = sum(1 for _, o in outcomes_list if o == AUTH_FAIL)
    silent_corruptions = sum(1 for _, o in outcomes_list if o == SILENT_CORRUPT)
    stream_breaks     = auth_failures + silent_corruptions
    total_bad         = stream_breaks
    loss_amplification = (total_bad / packets_dropped) if packets_dropped > 0 else None

    cascade_count, mean_cascade, max_cascade = analyse_cascades(outcomes_list)

    duration = (end_time - start_time) if start_time else 0.001
    eff_throughput = (bytes_decrypted / 1024) / duration

    summary = {
        "trial_id":                trial_id,
        "scheme":                  scheme,
        "loss_type":               loss_type,
        "loss_rate_pct":           loss_rate,
        "packets_sent":            NUM_PACKETS,
        "packets_received":        packets_received,
        "packets_dropped":         packets_dropped,
        "auth_failures":           auth_failures,
        "silent_corruptions":      silent_corruptions,
        "stream_breaks":           stream_breaks,
        "cascade_count":           cascade_count,
        "mean_cascade_length":     round(mean_cascade, 2),
        "max_cascade_length":      max_cascade,
        "loss_amplification":      round(loss_amplification, 3) if loss_amplification is not None else "",
        "effective_throughput_kbps": round(eff_throughput, 3),
        "trial_duration_s":        round(duration, 4),
        "timestamp":               time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    write_summary(summary)

    # Write per-packet log
    packet_rows = [
        {
            "trial_id":    trial_id,
            "scheme":      scheme,
            "loss_type":   loss_type,
            "loss_rate_pct": loss_rate,
            "seq":         seq,
            "outcome":     outcome,
        }
        for seq, outcome in outcomes_list
    ]
    write_packet_log(packet_rows)

    print(f"\n[SERVER] Trial done:")
    print(f"  Received:         {packets_received}/{NUM_PACKETS}")
    print(f"  Dropped:          {packets_dropped}")
    print(f"  Auth failures:    {auth_failures}")
    print(f"  Silent corrupt:   {silent_corruptions}")
    print(f"  Cascade count:    {cascade_count}")
    print(f"  Mean cascade len: {mean_cascade:.2f}")
    print(f"  Max cascade len:  {max_cascade}")
    print(f"  Loss amplif.:     {loss_amplification:.3f}")
    print(f"  Eff. throughput:  {eff_throughput:.2f} KB/s")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--scheme",   required=True, choices=list(SCHEME_IDS.keys()))
    p.add_argument("--trial",    type=int, default=1)
    p.add_argument("--losstype", default="standard", choices=["standard","burst","none"])
    p.add_argument("--lossrate", type=int, default=0)
    args = p.parse_args()
    run_server(args.scheme, args.trial, args.losstype, args.lossrate)
