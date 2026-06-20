import socket, struct, time, os, argparse
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hmac, hashes, padding
from cryptography.hazmat.backends import default_backend

AES_KEY    = bytes.fromhex("00" * 32)
CHACHA_KEY = bytes.fromhex("11" * 32)
HMAC_KEY   = bytes.fromhex("22" * 32)

SERVER_IP   = "10.0.0.2"
SERVER_PORT = 9999
PAYLOAD     = os.urandom(1024)

HEADER_FMT  = "!IBBHxx"
HEADER_SIZE = struct.calcsize(HEADER_FMT)

SCHEME_IDS = {
    "AES-GCM": 0, "ChaCha20-Poly1305": 1, "AES-CBC": 2, "ChaCha20-MAC": 3
}

def enc_aesgcm(seq):
    nonce = os.urandom(12)
    aesgcm = AESGCM(AES_KEY)
    ciphertext = aesgcm.encrypt(nonce, PAYLOAD, None)
    return nonce, ciphertext
def enc_chacha_poly1305(seq):
    nonce = os.urandom(12)
    chacha = ChaCha20Poly1305(CHACHA_KEY)
    ciphertext = chacha.encrypt(nonce, PAYLOAD, None)
    return nonce, ciphertext
def enc_aes_cbc(seq):
    iv =    os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(PAYLOAD) + padder.finalize()
    
    encryptor = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend()).encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    h =     hmac.HMAC(HMAC_KEY, hashes.SHA256(), backend=default_backend())
    h.update(iv + ciphertext)
    tag = h.finalize()
    return iv, ciphertext + tag
def enc_chacha_mac(seq):
    nonce = os.urandom(12)
    counter_block = (0).to_bytes(4, "little") + nonce
    encryptor = Cipher(algorithms.ChaCha20(CHACHA_KEY, counter_block), mode=None, backend=default_backend()).encryptor()
    ciphertext = encryptor.update(PAYLOAD) + encryptor.finalize()
    h =     hmac.HMAC(HMAC_KEY, hashes.SHA256(), backend=default_backend())
   
    h.update(nonce + ciphertext)
    tag = h.finalize()
    return nonce, ciphertext + tag
ENCRYPT_FN = {0: enc_aesgcm, 1: enc_chacha_poly1305,
              2: enc_aes_cbc,  3: enc_chacha_mac}

def run_client(scheme_id, num_packets, delay):
    scheme_id = SCHEME_IDS[scheme_id]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"Sending {num_packets} packets using scheme {scheme_id} with delay {delay}s...")
    for seq in range(num_packets):
        nonce, ciphertext = ENCRYPT_FN[scheme_id](seq)
        header = struct.pack(HEADER_FMT, seq, scheme_id, len(nonce), len(ciphertext))
        packet = header + nonce + ciphertext
        sock.sendto(packet, (SERVER_IP, SERVER_PORT))
        time.sleep(delay)
    sock.close()