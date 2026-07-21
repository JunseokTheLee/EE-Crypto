"""
server.py — EE Experiment Receiver
Run inside nsB: sudo ip netns exec nsB python3 server.py --scheme AES-GCM --packets 500 --trial 1 --losstype standard --lossrate 0
"""

import socket, struct, time, csv, os, argparse
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hmac, hashes
from cryptography.hazmat.backends import default_backend

# ── Shared keys (must match client.py) ────────────────────────────────────────
AES_KEY    = bytes.fromhex("00" * 32)
CHACHA_KEY = bytes.fromhex("11" * 32)
HMAC_KEY   = bytes.fromhex("22" * 32)

SERVER_IP   = "10.0.0.2"
SERVER_PORT = 9999
BUFFER_SIZE = 65535
CSV_FILE    = "results.csv"

# Known plaintext — must match PAYLOAD in client.py exactly.
# Used to detect silent corruption in unauthenticated schemes.
EXPECTED_PAYLOAD = bytes(range(256)) * 4   # 1024 bytes

HEADER_FMT  = "!IBBHxx"
HEADER_SIZE = struct.calcsize(HEADER_FMT)

SCHEME_IDS = {
    "AES-GCM":            0,
    "ChaCha20-Poly1305":  1,
    "AES-CBC":            2,
    "ChaCha20-MAC":       3,
    "AES-CBC-NOAUTH":     4,
    "ChaCha20-NOAUTH":    5,
}

# ── Decryption functions ───────────────────────────────────────────────────────

def decrypt_aesgcm(nonce, enc):
    return AESGCM(AES_KEY).decrypt(nonce, enc, None)

def decrypt_chacha20poly1305(nonce, enc):
    return ChaCha20Poly1305(CHACHA_KEY).decrypt(nonce, enc, None)

def decrypt_aescbc(nonce, body):
    mac_received = body[-32:]
    ciphertext   = body[:-32]
    h = hmac.HMAC(HMAC_KEY, hashes.SHA256(), backend=default_backend())
    h.update(nonce + ciphertext)
    h.verify(mac_received)
    decryptor = Cipher(
        algorithms.AES(AES_KEY), modes.CBC(nonce), backend=default_backend()
    ).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    return padded[:-padded[-1]]

def decrypt_chacha20mac(nonce, body):
    mac_received = body[-32:]
    ciphertext   = body[:-32]
    h = hmac.HMAC(HMAC_KEY, hashes.SHA256(), backend=default_backend())
    h.update(nonce + ciphertext)
    h.verify(mac_received)
    counter_block = (0).to_bytes(4, "little") + nonce[:12]
    decryptor = Cipher(
        algorithms.ChaCha20(CHACHA_KEY, counter_block), mode=None, backend=default_backend()
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def decrypt_aescbc_noauth(nonce, ciphertext):
    """AES-CBC with no MAC — decrypts without any authentication check."""
    decryptor = Cipher(
        algorithms.AES(AES_KEY), modes.CBC(nonce), backend=default_backend()
    ).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    pad_len = padded[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Bad padding")
    return padded[:-pad_len]

def decrypt_chacha20_noauth(nonce, ciphertext):
    """ChaCha20 with no MAC — decrypts without any authentication check."""
    counter_block = (0).to_bytes(4, "little") + nonce[:12]
    decryptor = Cipher(
        algorithms.ChaCha20(CHACHA_KEY, counter_block), mode=None, backend=default_backend()
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

DECRYPT_FN = {
    0: decrypt_aesgcm,
    1: decrypt_chacha20poly1305,
    2: decrypt_aescbc,
    3: decrypt_chacha20mac,
    4: decrypt_aescbc_noauth,
    5: decrypt_chacha20_noauth,
}

# ── CSV helpers ────────────────────────────────────────────────────────────────

FIELDS = ["trial_id","scheme","loss_type","loss_rate_pct","packets_sent",
          "packets_received","auth_failures","silent_corruptions",
          "throughput_kbps","trial_duration_s","timestamp"]

def init_csv():
    if not os.path.exists(CSV_FILE):
        with open(CSV_FILE, "w", newline="") as f:
            csv.writer(f).writerow(FIELDS)

def write_csv(row):
    with open(CSV_FILE, "a", newline="") as f:
        csv.DictWriter(f, fieldnames=FIELDS).writerow(row)

# ── Main server loop ───────────────────────────────────────────────────────────

def run_server(scheme, total_packets, trial_id, loss_type, loss_rate):
    scheme_id = SCHEME_IDS[scheme]
    is_unauth = scheme_id in (4, 5)   # unauthenticated schemes
    init_csv()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((SERVER_IP, SERVER_PORT))
    sock.settimeout(5.0)

    print(f"[SERVER] {scheme} | trial={trial_id} | {loss_type} {loss_rate}%")
    print(f"[SERVER] Listening on {SERVER_IP}:{SERVER_PORT} ...")

    packets_received    = 0
    auth_failures       = 0
    silent_corruptions  = 0   # only non-zero for unauthenticated schemes
    bytes_decrypted     = 0
    start_time = end_time = None
    seen_seqs  = set()

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
            print("[SERVER] DONE signal received.")
            break

        if len(data) < HEADER_SIZE:
            continue

        seq_num, recv_id, nonce_len, payload_len = struct.unpack(HEADER_FMT, data[:HEADER_SIZE])

        if recv_id != scheme_id:
            continue

        if seq_num in seen_seqs:
            continue
        seen_seqs.add(seq_num)

        packets_received += 1

        body  = data[HEADER_SIZE:]
        nonce = body[:nonce_len]
        enc   = body[nonce_len:]

        try:
            plaintext = DECRYPT_FN[scheme_id](nonce, enc)
            bytes_decrypted += len(plaintext)

            # For unauthenticated schemes: compare plaintext to known payload.
            # If they differ, corruption passed through silently.
            if is_unauth and plaintext != EXPECTED_PAYLOAD:
                silent_corruptions += 1
                print(f"  seq={seq_num:04d}  SILENT CORRUPTION (no auth to catch it)")

        except Exception as e:
            auth_failures += 1
            print(f"  seq={seq_num:04d}  AUTH FAILURE ({type(e).__name__})")

        if packets_received >= total_packets:
            print("[SERVER] All packets received.")
            break

    sock.close()

    duration = (end_time - start_time) if start_time else 0.001
    throughput_kbps = (bytes_decrypted / 1024) / duration

    row = {
        "trial_id":            trial_id,
        "scheme":              scheme,
        "loss_type":           loss_type,
        "loss_rate_pct":       loss_rate,
        "packets_sent":        total_packets,
        "packets_received":    packets_received,
        "auth_failures":       auth_failures,
        "silent_corruptions":  silent_corruptions,
        "throughput_kbps":     round(throughput_kbps, 3),
        "trial_duration_s":    round(duration, 4),
        "timestamp":           time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    write_csv(row)

    print(f"\n[SERVER] Trial done:")
    print(f"  Received:           {packets_received}/{total_packets}")
    print(f"  Auth failures:      {auth_failures}")
    print(f"  Silent corruptions: {silent_corruptions}")
    print(f"  Throughput:         {throughput_kbps:.2f} KB/s")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--scheme", required=True, choices=list(SCHEME_IDS.keys()))
    p.add_argument("--packets",  type=int, default=500)
    p.add_argument("--trial",    type=int, default=1)
    p.add_argument("--losstype", default="standard",
                   choices=["standard","burst","corrupt"])
    p.add_argument("--lossrate", type=int, default=0)
    args = p.parse_args()
    run_server(args.scheme, args.packets, args.trial, args.losstype, args.lossrate)
