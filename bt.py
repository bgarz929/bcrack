import os
import sys
import time
import random
import hashlib
import requests
import base58
import threading
from multiprocessing import Process, Queue, cpu_count, Event, Value
from ecdsa import SECP256k1, SigningKey
from datetime import datetime

# ========== KONFIGURASI ==========
NUM_PROCESSES = max(1, cpu_count() - 1)  # Gunakan semua core kecuali 1
CHECK_BALANCE = True                     # Set False jika hanya ingin generate offline (sangat cepat)
RICH_LOG_FILE = "found_rich.txt"
WALLETS_LOG_FILE = "generated_wallets.txt"

# ========== API PROVIDERS (Load Balancer) ==========
# Kita merotasi API untuk menghindari Rate Limit
API_SOURCES = [
    "https://blockchain.info/q/addressbalance/{}",
    "https://mempool.space/api/address/{}/utxo",  # Mempool returns list, need parsing
    "https://blockstream.info/api/address/{}/utxo"
]

# ========== FUNGSI KRIPTOGRAFI (Bitcoin Standard) ==========

def generate_private_key():
    """Generate random private key hex 32 bytes"""
    return os.urandom(32).hex()

def private_key_to_wif(private_key_hex, compressed=True):
    """Convert Hex Private Key ke WIF (Wallet Import Format)"""
    extended_key = b"\x80" + bytes.fromhex(private_key_hex)
    if compressed:
        extended_key += b"\x01"
    
    first_sha = hashlib.sha256(extended_key).digest()
    second_sha = hashlib.sha256(first_sha).digest()
    checksum = second_sha[:4]
    
    wif = base58.b58encode(extended_key + checksum)
    return wif.decode('utf-8')

def private_key_to_public_key(private_key_hex, compressed=True):
    """Generate Public Key dari Private Key menggunakan kurva SECP256k1"""
    sk = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)
    vk = sk.verifying_key
    
    if compressed:
        from ecdsa.util import sigencode_string
        # Compressed public key format:
        # 0x02 + x (jika y genap) ATAU 0x03 + x (jika y ganjil)
        x_str = vk.to_string()[:32]
        y_str = vk.to_string()[32:]
        if int.from_bytes(y_str, byteorder='big') % 2 == 0:
            return (b'\x02' + x_str).hex()
        else:
            return (b'\x03' + x_str).hex()
    else:
        return (b'\x04' + vk.to_string()).hex()

def public_key_to_address(public_key_hex):
    """Convert Public Key Hex ke Bitcoin Address (P2PKH)"""
    public_key_bytes = bytes.fromhex(public_key_hex)
    
    # 1. SHA-256
    sha256_bpk = hashlib.sha256(public_key_bytes).digest()
    
    # 2. RIPEMD-160
    ripemd160_bpk = hashlib.new('ripemd160')
    ripemd160_bpk.update(sha256_bpk)
    ripemd160_bpk_digest = ripemd160_bpk.digest()
    
    # 3. Add Network Byte (0x00 for Mainnet)
    network_byte = b'\x00' + ripemd160_bpk_digest
    
    # 4. Double SHA-256 for Checksum
    sha256_nb = hashlib.sha256(network_byte).digest()
    sha256_2_nb = hashlib.sha256(sha256_nb).digest()
    checksum = sha256_2_nb[:4]
    
    # 5. Base58 Encode
    address = base58.b58encode(network_byte + checksum)
    return address.decode('utf-8')

# ========== BALANCER CHECKER ==========

def check_balance(address):
    """Check balance dengan rotasi API dan Error Handling"""
    if not CHECK_BALANCE:
        return 0
    
    # Randomly pick API source to distribute load
    source = random.choice(API_SOURCES)
    url = source.format(address)
    
    try:
        response = requests.get(url, timeout=5)
        
        if response.status_code == 200:
            # Handle Blockchain.info (returns raw integer)
            if "blockchain.info" in url:
                return int(response.text)
            
            # Handle Mempool/Blockstream (returns JSON UTXO list)
            elif "utxo" in url:
                data = response.json()
                total_sats = sum([utxo['value'] for utxo in data])
                return total_sats
                
        # Jika gagal atau rate limit, kembalikan 0 (atau bisa ditambahkan logic retry)
        return 0
        
    except Exception:
        return 0

# ========== WORKER PROCESS ==========

def worker(queue, found_event, counter_val):
    """Fungsi yang dijalankan oleh setiap Core CPU"""
    sys.stdout.flush()
    
    while not found_event.is_set():
        try:
            # 1. Generate Keys
            priv_hex = generate_private_key()
            wif = private_key_to_wif(priv_hex, compressed=True)
            pub_hex = private_key_to_public_key(priv_hex, compressed=True)
            address = public_key_to_address(pub_hex)
            
            # 2. Check Balance
            balance = 0
            if CHECK_BALANCE:
                balance = check_balance(address)
            
            # 3. Kirim ke Main Process jika ada hasil menarik
            # Simpan log setiap wallet (opsional, hati-hati file size meledak)
            # Untuk efisiensi, kita hanya kirim data ke queue display setiap 50 generate
            
            with counter_val.get_lock():
                counter_val.value += 1
                
            if balance > 0:
                result = {
                    "type": "RICH",
                    "address": address,
                    "private_key": wif,
                    "balance": balance
                }
                queue.put(result)
                
            # Uncomment baris bawah jika ingin menyimpan SEMUA wallet (sangat memperlambat disk I/O)
            # else:
            #     queue.put({"type": "NORMAL", "address": address, "wif": wif})
            
        except Exception as e:
            continue

# ========== MAIN MONITOR ==========

def print_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"""
    ╔══════════════════════════════════════════════════════════╗
    ║             BITCOIN HUNTER OPTIMIZED v4.0                ║
    ║        Multi-Process & Valid Cryptography Engine         ║
    ╚══════════════════════════════════════════════════════════╝
    [+] CPU Cores    : {cpu_count()} Detected
    [+] Workers      : {NUM_PROCESSES} Active
    [+] Balance Check: {'ENABLED' if CHECK_BALANCE else 'DISABLED'}
    [+] Output File  : {RICH_LOG_FILE}
    """)

def main():
    print_banner()
    
    # Shared variables antar proses
    result_queue = Queue()
    found_event = Event()
    counter = Value('i', 0)
    
    # Start Worker Processes
    processes = []
    for _ in range(NUM_PROCESSES):
        p = Process(target=worker, args=(result_queue, found_event, counter))
        p.start()
        processes.append(p)
    
    start_time = time.time()
    
    try:
        while True:
            # Update Display
            time.sleep(1)
            elapsed = time.time() - start_time
            total = counter.value
            speed = total / elapsed if elapsed > 0 else 0
            
            sys.stdout.write(
                f"\r[*] Scanned: {total:,} Wallets | "
                f"Speed: {speed:.2f} keys/sec | "
                f"Time: {elapsed:.1f}s"
            )
            sys.stdout.flush()
            
            # Check Queue for Results
            while not result_queue.empty():
                data = result_queue.get()
                
                if data['type'] == 'RICH':
                    print("\n\n" + "!"*50)
                    print(f" [SUCCESS] FOUND BALANCE!")
                    print(f" Address : {data['address']}")
                    print(f" PrivKey : {data['private_key']}")
                    print(f" Balance : {data['balance']} sats")
                    print("!"*50 + "\n")
                    
                    with open(RICH_LOG_FILE, "a") as f:
                        f.write(f"Address: {data['address']} | Key: {data['private_key']} | Bal: {data['balance']}\n")
                        
    except KeyboardInterrupt:
        print("\n\n[!] Stopping all workers...")
        found_event.set()
        for p in processes:
            p.terminate()
        print("[!] Cleanup complete. Goodbye.")

if __name__ == "__main__":
    # Windows fix untuk multiprocessing
    try:
        import multiprocessing
        multiprocessing.freeze_support()
    except:
        pass
        
    main()
