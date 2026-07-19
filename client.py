"""
client.py — EE Experiment Sender
Run inside nsA: sudo ip netns exec nsA python3 client.py --scheme AES-GCM --packets 500
"""

import socket, struct, time, os, argparse
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
PAYLOAD     = os.urandom(1024)   # 1024 bytes of random plaintext, fixed for all trials

HEADER_FMT  = "!IBBHxx"
HEADER_SIZE = struct.calcsize(HEADER_FMT)

SCHEME_IDS = {
    "AES-GCM": 0, "ChaCha20-Poly1305": 1, "AES-CBC": 2, "ChaCha20-MAC": 3
}

# ── Encryption functions ───────────────────────────────────────────────────────

def encrypt_aesgcm(seq):
    nonce = os.urandom(12)
    ct    = AESGCM(AES_KEY).encrypt(nonce, PAYLOAD, None)
    return nonce, ct

def encrypt_chacha20poly1305(seq):
    nonce = os.urandom(12)
    ct    = ChaCha20Poly1305(CHACHA_KEY).encrypt(nonce, PAYLOAD, None)
    return nonce, ct

def encrypt_aescbc(seq):
    """AES-CBC with PKCS7 padding + HMAC-SHA256 (Encrypt-then-MAC)."""
    iv = os.urandom(16)

    # PKCS7 pad plaintext to block boundary
    padder  = padding.PKCS7(128).padder()
    padded  = padder.update(PAYLOAD) + padder.finalize()

    encryptor = Cipher(
        algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    # MAC over IV + ciphertext
    h = hmac.HMAC(HMAC_KEY, hashes.SHA256(), backend=default_backend())
    h.update(iv + ciphertext)
    mac = h.finalize()

    return iv, ciphertext + mac   # nonce=IV, body=ciphertext||MAC

def encrypt_chacha20mac(seq):
    """ChaCha20 stream + HMAC-SHA256."""
    nonce = os.urandom(12)
    counter_block = (0).to_bytes(4, "little") + nonce
    encryptor = Cipher(
        algorithms.ChaCha20(CHACHA_KEY, counter_block), mode=None, backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(PAYLOAD) + encryptor.finalize()

    h = hmac.HMAC(HMAC_KEY, hashes.SHA256(), backend=default_backend())
    h.update(nonce + ciphertext)
    mac = h.finalize()

    return nonce, ciphertext + mac

ENCRYPT_FN = {0: encrypt_aesgcm, 1: encrypt_chacha20poly1305,
              2: encrypt_aescbc,  3: encrypt_chacha20mac}

# ── Main sender loop ───────────────────────────────────────────────────────────

def corrupt_tag(body, corrupt_rate):
    """
    Flip the last byte of the tag/MAC on a given percentage of packets.
    For AEAD: tag is the last 16 bytes of body.
    For Non-AEAD: MAC is the last 32 bytes of body.
    Flipping even one byte guaranteed causes authentication failure.
    """
    import random
    if random.random() < (corrupt_rate / 100):
        body = bytearray(body)
        body[-1] ^= 0xFF   # flip last byte of tag/MAC
        body = bytes(body)
    return body


def run_client(scheme, total_packets, delay_s=0.002, corrupt_rate=0):
    scheme_id = SCHEME_IDS[scheme]

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print(f"[CLIENT] {scheme} | sending {total_packets} packets to {SERVER_IP}:{SERVER_PORT}")
    if corrupt_rate > 0:
        print(f"[CLIENT] Corrupt mode: {corrupt_rate}% of packets will have tag/MAC corrupted")

    for seq in range(total_packets):
        nonce, body = ENCRYPT_FN[scheme_id](seq)

        # Corrupt tag/MAC bytes at the specified rate
        if corrupt_rate > 0:
            body = corrupt_tag(body, corrupt_rate)

        # Build header: seq_num, scheme_id, nonce_len, payload_len
        header = struct.pack(HEADER_FMT, seq, scheme_id, len(nonce), len(PAYLOAD))
        datagram = header + nonce + body

        sock.sendto(datagram, (SERVER_IP, SERVER_PORT))

        if (seq + 1) % 100 == 0:
            print(f"  Sent {seq + 1}/{total_packets}")

        time.sleep(delay_s)

    # Send DONE signal 10 times so server exits cleanly even under loss
    for _ in range(10):
        sock.sendto(b"DONE", (SERVER_IP, SERVER_PORT))
        time.sleep(0.05)

    sock.close()
    print(f"[CLIENT] Done — {total_packets} packets sent.")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--scheme", required=True,
                   choices=["AES-GCM","ChaCha20-Poly1305","AES-CBC","ChaCha20-MAC"])
    p.add_argument("--packets",  type=int,   default=500)
    p.add_argument("--delay",    type=float, default=0.002)
    p.add_argument("--corrupt",  type=int,   default=0,
                   help="Percentage of packets to corrupt the tag/MAC on (0-100)")
    args = p.parse_args()
    run_client(args.scheme, args.packets, args.delay, args.corrupt)
