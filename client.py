"""
client.py — EE Experiment Sender
Run inside nsA: sudo ip netns exec nsA python3 client.py --scheme AES-GCM --packets 500
"""

import socket, struct, time, os, argparse, random
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hmac, hashes, padding
from cryptography.hazmat.backends import default_backend

# ── Shared keys (must match server.py) ────────────────────────────────────────
AES_KEY    = bytes.fromhex("00" * 32)
CHACHA_KEY = bytes.fromhex("11" * 32)
HMAC_KEY   = bytes.fromhex("22" * 32)

SERVER_IP   = "10.0.0.2"
SERVER_PORT = 9999

# Fixed plaintext payload — same for every packet in every trial.
# Server uses this to detect silent corruption in unauthenticated schemes.
PAYLOAD = bytes(range(256)) * 4   # 1024 bytes, deterministic so server knows it too

HEADER_FMT  = "!IBBHxx"
HEADER_SIZE = struct.calcsize(HEADER_FMT)

SCHEME_IDS = {
    "AES-GCM":            0,
    "ChaCha20-Poly1305":  1,
    "AES-CBC":            2,
    "ChaCha20-MAC":       3,
    "AES-CBC-NOAUTH":     4,   # unauthenticated
    "ChaCha20-NOAUTH":    5,   # unauthenticated
}

# ── Encryption functions ───────────────────────────────────────────────────────

def encrypt_aesgcm(seq):
    nonce = os.urandom(12)
    return nonce, AESGCM(AES_KEY).encrypt(nonce, PAYLOAD, None)

def encrypt_chacha20poly1305(seq):
    nonce = os.urandom(12)
    return nonce, ChaCha20Poly1305(CHACHA_KEY).encrypt(nonce, PAYLOAD, None)

def encrypt_aescbc(seq):
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(PAYLOAD) + padder.finalize()
    encryptor = Cipher(
        algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    h = hmac.HMAC(HMAC_KEY, hashes.SHA256(), backend=default_backend())
    h.update(iv + ciphertext)
    return iv, ciphertext + h.finalize()

def encrypt_chacha20mac(seq):
    nonce = os.urandom(12)
    counter_block = (0).to_bytes(4, "little") + nonce
    encryptor = Cipher(
        algorithms.ChaCha20(CHACHA_KEY, counter_block), mode=None, backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(PAYLOAD) + encryptor.finalize()
    h = hmac.HMAC(HMAC_KEY, hashes.SHA256(), backend=default_backend())
    h.update(nonce + ciphertext)
    return nonce, ciphertext + h.finalize()

def encrypt_aescbc_noauth(seq):
    """AES-CBC with NO MAC — unauthenticated."""
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(PAYLOAD) + padder.finalize()
    encryptor = Cipher(
        algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend()
    ).encryptor()
    return iv, encryptor.update(padded) + encryptor.finalize()

def encrypt_chacha20_noauth(seq):
    """ChaCha20 stream with NO MAC — unauthenticated."""
    nonce = os.urandom(12)
    counter_block = (0).to_bytes(4, "little") + nonce
    encryptor = Cipher(
        algorithms.ChaCha20(CHACHA_KEY, counter_block), mode=None, backend=default_backend()
    ).encryptor()
    return nonce, encryptor.update(PAYLOAD) + encryptor.finalize()

ENCRYPT_FN = {
    0: encrypt_aesgcm,
    1: encrypt_chacha20poly1305,
    2: encrypt_aescbc,
    3: encrypt_chacha20mac,
    4: encrypt_aescbc_noauth,
    5: encrypt_chacha20_noauth,
}

# ── Corruption helper ──────────────────────────────────────────────────────────

def corrupt_body(body, scheme_id, corrupt_rate):
    """
    Flip a byte in the body at the given rate.
    For authenticated schemes (0-3): flip last byte of tag/MAC — guaranteed auth failure.
    For unauthenticated schemes (4-5): flip a byte in the middle of ciphertext —
    will corrupt plaintext silently with no detection.
    """
    if random.random() < (corrupt_rate / 100):
        body = bytearray(body)
        if scheme_id in (4, 5):
            body[len(body) // 2] ^= 0xFF   # flip mid-ciphertext byte
        else:
            body[-1] ^= 0xFF               # flip last byte of tag/MAC
        body = bytes(body)
    return body

# ── Main sender loop ───────────────────────────────────────────────────────────

def run_client(scheme, total_packets, delay_s=0.002, corrupt_rate=0):
    scheme_id = SCHEME_IDS[scheme]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print(f"[CLIENT] {scheme} | sending {total_packets} packets to {SERVER_IP}:{SERVER_PORT}")
    if corrupt_rate > 0:
        print(f"[CLIENT] Corrupt mode: {corrupt_rate}% of packets will be corrupted")

    for seq in range(total_packets):
        nonce, body = ENCRYPT_FN[scheme_id](seq)

        if corrupt_rate > 0:
            body = corrupt_body(body, scheme_id, corrupt_rate)

        header = struct.pack(HEADER_FMT, seq, scheme_id, len(nonce), len(PAYLOAD))
        sock.sendto(header + nonce + body, (SERVER_IP, SERVER_PORT))

        if (seq + 1) % 100 == 0:
            print(f"  Sent {seq + 1}/{total_packets}")

        time.sleep(delay_s)

    for _ in range(10):
        sock.sendto(b"DONE", (SERVER_IP, SERVER_PORT))
        time.sleep(0.05)

    sock.close()
    print(f"[CLIENT] Done — {total_packets} packets sent.")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--scheme", required=True,
                   choices=list(SCHEME_IDS.keys()))
    p.add_argument("--packets",  type=int,   default=500)
    p.add_argument("--delay",    type=float, default=0.002)
    p.add_argument("--corrupt",  type=int,   default=0)
    args = p.parse_args()
    run_client(args.scheme, args.packets, args.delay, args.corrupt)
