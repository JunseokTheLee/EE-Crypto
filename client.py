"""
client.py — Cascade Length EE Experiment
Three schemes, stateful stream, standard and burst loss only.
"""

import socket, struct, time, os, argparse
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hmac, hashes, padding as sym_padding
from cryptography.hazmat.backends import default_backend

AES_KEY  = bytes.fromhex("00" * 32)
HMAC_KEY = bytes.fromhex("22" * 32)

SERVER_IP   = "10.0.0.2"
SERVER_PORT = 9999

CHUNK_SIZE  = 256
NUM_PACKETS = 500
STREAM_DATA = bytes([i % 256 for i in range(NUM_PACKETS * CHUNK_SIZE)])

HEADER_FMT  = "!IBBHxx"
HEADER_SIZE = struct.calcsize(HEADER_FMT)

SCHEME_IDS = {
    "AES-GCM":       0,
    "AES-CBC":       1,
    "AES-CBC-NOAUTH": 2,
}

# ── Stateful encryptors ────────────────────────────────────────────────────────

class EncryptAESGCM:
    """
    Sequential nonce = base(4B) + seq(8B).
    Each packet independently decryptable — no cross-packet state.
    """
    def __init__(self):
        self.base  = os.urandom(4)
        self.gcm   = AESGCM(AES_KEY)

    def encrypt(self, seq, chunk):
        nonce = self.base + seq.to_bytes(8, "big")
        return nonce, self.gcm.encrypt(nonce, chunk, None)


class EncryptAESCBC:
    """
    IV for packet N = last 16 bytes of packet N-1 ciphertext.
    Cross-packet chaining — one lost packet cascades into all subsequent ones.
    HMAC-SHA256 appended for authentication.
    """
    def __init__(self):
        self.prev_ct_block = os.urandom(16)

    def encrypt(self, seq, chunk):
        padder = sym_padding.PKCS7(128).padder()
        padded = padder.update(chunk) + padder.finalize()
        encryptor = Cipher(
            algorithms.AES(AES_KEY), modes.CBC(self.prev_ct_block),
            backend=default_backend()
        ).encryptor()
        ct = encryptor.update(padded) + encryptor.finalize()
        self.prev_ct_block = ct[-16:]
        h = hmac.HMAC(HMAC_KEY, hashes.SHA256(), backend=default_backend())
        h.update(self.prev_ct_block + ct)
        return self.prev_ct_block, ct + h.finalize()


class EncryptAESCBCNoAuth:
    """AES-CBC chained across packets, no MAC."""
    def __init__(self):
        self.prev_ct_block = os.urandom(16)

    def encrypt(self, seq, chunk):
        padder = sym_padding.PKCS7(128).padder()
        padded = padder.update(chunk) + padder.finalize()
        encryptor = Cipher(
            algorithms.AES(AES_KEY), modes.CBC(self.prev_ct_block),
            backend=default_backend()
        ).encryptor()
        ct = encryptor.update(padded) + encryptor.finalize()
        self.prev_ct_block = ct[-16:]
        return self.prev_ct_block, ct


ENCRYPTORS = {0: EncryptAESGCM, 1: EncryptAESCBC, 2: EncryptAESCBCNoAuth}


def run_client(scheme, delay_s=0.002):
    scheme_id = SCHEME_IDS[scheme]
    enc  = ENCRYPTORS[scheme_id]()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print(f"[CLIENT] {scheme} | {NUM_PACKETS} packets")

    for seq in range(NUM_PACKETS):
        chunk = STREAM_DATA[seq * CHUNK_SIZE:(seq + 1) * CHUNK_SIZE]
        nonce, body = enc.encrypt(seq, chunk)
        header = struct.pack(HEADER_FMT, seq, scheme_id, len(nonce), CHUNK_SIZE)
        sock.sendto(header + nonce + body, (SERVER_IP, SERVER_PORT))

        if (seq + 1) % 100 == 0:
            print(f"  Sent {seq + 1}/{NUM_PACKETS}")
        time.sleep(delay_s)

    for _ in range(10):
        sock.sendto(b"DONE", (SERVER_IP, SERVER_PORT))
        time.sleep(0.05)

    sock.close()
    print("[CLIENT] Done.")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--scheme", required=True, choices=list(SCHEME_IDS.keys()))
    p.add_argument("--delay",  type=float, default=0.002)
    args = p.parse_args()
    run_client(args.scheme, args.delay)
