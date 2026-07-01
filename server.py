import socket, struct, time, os, argparse
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hmac, hashes, padding
from cryptography.hazmat.backends import default_backend
import csv, datetime
SERVER_IP   = "10.0.0.2"
SERVER_PORT = 9999
BUFFER_SIZE = 65535
CSV_FILE    = "results.csv"
AES_KEY    = bytes.fromhex("00" * 32)   # 256-bit AES key
CHACHA_KEY = bytes.fromhex("11" * 32)   # 256-bit ChaCha20 key
HMAC_KEY   = bytes.fromhex("22" * 32)   # 256-bit HMAC key (Non-AEAD only)  
HEADER_FMT  = "!IBBHxx"
HEADER_SIZE = struct.calcsize(HEADER_FMT)   # = 8 bytes
 
SCHEME_IDS = {
    "AES-GCM": 0, "ChaCha20-Poly1305": 1, "AES-CBC": 2, "ChaCha20-MAC": 3
}
def decrypt_aesgcm(nonce, ciphertext):
    aesgcm = AESGCM(AES_KEY)
    return aesgcm.decrypt(nonce, ciphertext, None)
def decrypt_chacha_poly1305(nonce, ciphertext):
    chacha = ChaCha20Poly1305(CHACHA_KEY)
    return chacha.decrypt(nonce, ciphertext, None)
def decrypt_aes_cbc(iv, ciphertext_tag):
    ciphertext, tag = ciphertext_tag[:-32], ciphertext_tag[-32:]
    h =     hmac.HMAC(HMAC_KEY, hashes.SHA256(), backend=default_backend())
    h.update(iv + ciphertext)
    h.verify(tag)
    
    decryptor = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend()).decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()   
def decrypt_chacha_mac(nonce, ciphertext_tag):
    ciphertext, tag = ciphertext_tag[:-32], ciphertext_tag[-32:]
    h =     hmac.HMAC(HMAC_KEY, hashes.SHA256(), backend=default_backend())
    h.update(nonce + ciphertext)
    h.verify(tag)
    
    counter_block = (0).to_bytes(4, "little") + nonce
    decryptor = Cipher(algorithms.ChaCha20(CHACHA_KEY, counter_block), mode=None, backend=default_backend()).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

 
DECRYPT_FN = {0: decrypt_aesgcm, 1: decrypt_chacha_poly1305,
              2: decrypt_aes_cbc,  3: decrypt_chacha_mac}

FIELDS = ["trial_id","scheme","loss_type","loss_rate_pct","packets_sent",
          "packets_received","auth_failures","throughput_kbps","trial_duration_s","timestamp"]
 
def init_csv():
    if not os.path.exists(CSV_FILE):
        with open(CSV_FILE, "w", newline="") as f:
            csv.writer(f).writerow(FIELDS)
 
def write_csv(row):
    with open(CSV_FILE, "a", newline="") as f:
        csv.DictWriter(f, fieldnames=FIELDS).writerow(row)

def run_server(scheme, total_packets, trial_id, loss_type, loss_rate_pct):
    scheme_id = SCHEME_IDS[scheme]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((SERVER_IP, SERVER_PORT))
    print(f"Listening on {SERVER_IP}:{SERVER_PORT} for scheme {scheme}...")
    
    packets_received = 0
    auth_failures = 0
    start_time = end_time=None
    bytes_decrypted = 0
    seen_seqs = set()

    while True:
        try:
            data, addr = sock.recvfrom(BUFFER_SIZE)
        except socket.timeout:
            continue
        if start_time is None:
            start_time = time.perf_counter()
        end_time   = time.perf_counter()
        if len(data) < HEADER_SIZE:
            print("Received packet too short for header, ignoring")
            continue
        seq_num, recv_id, nonce_len, ciphertext_len = struct.unpack(HEADER_FMT, data[:HEADER_SIZE])
        if recv_id != scheme_id:
            print(f"Received packet with unexpected scheme ID {recv_id}, ignoring")
            continue
        if seq_num in seen_seqs:
            print(f"Received duplicate packet with sequence number {seq_num}, ignoring")
            continue
        seen_seqs.add(seq_num)
        packets_received += 1
        body = data[HEADER_SIZE:]
        nonce = body[:nonce_len]
        enc = body[nonce_len:]
        try:
            plaintext = DECRYPT_FN[scheme_id](nonce, enc)
            bytes_decrypted += len(plaintext)
        except Exception as e:
            auth_failures += 1
            print(f"  seq={seq_num:04d}  AUTH FAILURE ({type(e).__name__})")
 
    sock.close()
    duration = end_time - start_time if start_time and end_time else 0.01
    throughput_kbps = (bytes_decrypted / 1024) / duration
    row = {
        "trial_id":         trial_id,
        "scheme":           scheme,
        "loss_type":        loss_type,
        "loss_rate_pct":    loss_rate,
        "packets_sent":     total_packets,
        "packets_received": packets_received,
        "auth_failures":    auth_failures,
        "throughput_kbps":  round(throughput_kbps, 3),
        "trial_duration_s": round(duration, 4),
        "timestamp":        time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    write_csv(row)
 
    print(f"\n[SERVER] Trial done:")
    print(f"  Received:      {packets_received}/{total_packets}")
    print(f"  Auth failures: {auth_failures}")
    print(f"  Throughput:    {throughput_kbps:.2f} KB/s")
    print(f"  Duration:      {duration:.3f}s")
if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--scheme",   required=True,
                   choices=["AES-GCM","ChaCha20-Poly1305","AES-CBC","ChaCha20-MAC"])
    p.add_argument("--packets",  type=int, default=500)
    p.add_argument("--trial",    type=int, default=1)
    p.add_argument("--losstype", default="standard", choices=["standard","burst"])
    p.add_argument("--lossrate", type=int, default=0)
    args = p.parse_args()
    run_server(args.scheme, args.packets, args.trial, args.losstype, args.lossrate)