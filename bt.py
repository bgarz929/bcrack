import os
import sys
import time
import hashlib
import asyncio
import ssl
import random
import logging
import base58
from multiprocessing import Process, Queue, cpu_count, Value, Event
from ecdsa import SECP256k1, SigningKey

# ========== CEK DEPENDENCIES & HASH FIX ==========
# Ini adalah bagian perbaikan untuk error "unsupported hash type ripemd160"

def get_ripemd160_hasher():
    """Mencari penyedia algoritma RIPEMD160 yang tersedia"""
    try:
        # Coba cara standar (biasanya gagal di Python baru/OpenSSL 3)
        hashlib.new('ripemd160')
        return "hashlib"
    except ValueError:
        try:
            # Coba gunakan pycryptodome (Library eksternal)
            from Crypto.Hash import RIPEMD160
            return "pycryptodome"
        except ImportError:
            print("\n❌ CRITICAL ERROR: Sistem Anda tidak mendukung RIPEMD160.")
            print("👉 Solusi: Jalankan perintah 'pip install pycryptodome' di terminal.\n")
            sys.exit(1)

HASH_PROVIDER = get_ripemd160_hasher()

def calc_ripemd160(data_bytes):
    """Fungsi wrapper untuk menghitung RIPEMD160"""
    if HASH_PROVIDER == "hashlib":
        h = hashlib.new('ripemd160')
        h.update(data_bytes)
        return h.digest()
    else:
        # Gunakan pycryptodome
        from Crypto.Hash import RIPEMD160
        h = RIPEMD160.new()
        h.update(data_bytes)
        return h.digest()

# Coba import library aiorpcx (Engine Electrum)
try:
    from aiorpcx import connect_rs
except ImportError:
    print("❌ Library 'aiorpcx' belum diinstall.")
    print("👉 Jalankan: pip install aiorpcx")
    sys.exit(1)

# ========== KONFIGURASI ==========
NUM_PROCESSES = max(1, cpu_count() - 1)
BATCH_SIZE = 50 
RICH_LOG_FILE = "found_rich.txt"

# Server Electrum Stabil (SSL Port 50002)
ELECTRUM_SERVERS = [
    ("electrum.blockstream.info", 50002),
    ("electrum.emzy.de", 50002),
    ("bitcoin.lukechilds.co", 50002),
    ("electrum.bitaroo.net", 50002),
    ("ssl.mercurywallet.com", 50002),
    ("electrum.jochen-hoenicke.de", 50002),
]

# ========== 1. GENERATOR (Fix RIPEMD160) ==========

def generate_key_pair():
    """Membuat Private Key, WIF, dan Address P2PKH"""
    priv_bytes = os.urandom(32)
    
    # WIF Compressed
    extended_key = b"\x80" + priv_bytes + b"\x01"
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    wif = base58.b58encode(extended_key + checksum).decode('utf-8')
    
    # Public Key
    sk = SigningKey.from_string(priv_bytes, curve=SECP256k1)
    vk = sk.verifying_key
    x_str = vk.to_string()[:32]
    y_str = vk.to_string()[32:]
    
    if int.from_bytes(y_str, byteorder='big') % 2 == 0:
        pub_key_bytes = b'\x02' + x_str
    else:
        pub_key_bytes = b'\x03' + x_str
        
    # Address P2PKH Generation
    sha256_bpk = hashlib.sha256(pub_key_bytes).digest()
    
    # --- BAGIAN YANG DIPERBAIKI ---
    # Menggunakan fungsi wrapper yang aman dari error OpenSSL
    ripemd160_digest = calc_ripemd160(sha256_bpk)
    # ------------------------------
    
    network_byte = b'\x00' + ripemd160_digest
    checksum_addr = hashlib.sha256(hashlib.sha256(network_byte).digest()).digest()[:4]
    address = base58.b58encode(network_byte + checksum_addr).decode('utf-8')
    
    return wif, address

# ========== 2. FUNGSI ELECTRUM (Engine cebb.py) ==========

def address_to_scripthash(address):
    """Convert Address -> ScriptHash (SHA256 Reversed)"""
    try:
        decoded = base58.b58decode_check(address)
        if decoded[0] != 0: 
            return None 
        pubkey_hash = decoded[1:]
        script = b'\x76\xa9\x14' + pubkey_hash + b'\x88\xac'
        h = hashlib.sha256(script).digest()
        return h[::-1].hex()
    except:
        return None

async def worker_logic(queue, counter):
    """Worker Logic dengan Auto-Switch Server"""
    
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    while True:
        # Pilih server acak
        server = random.choice(ELECTRUM_SERVERS)
        host, port = server

        try:
            # print(f"🔗 Connecting to {host}...") # Uncomment untuk debug
            async with connect_rs(host, port, ssl=ssl_ctx) as session:
                # Jika berhasil konek
                while True:
                    # 1. Generate Batch
                    batch_data = {} 
                    batch_scripthashes = []
                    
                    for _ in range(BATCH_SIZE):
                        wif, addr = generate_key_pair()
                        sh = address_to_scripthash(addr)
                        if sh:
                            batch_data[addr] = wif
                            batch_scripthashes.append((addr, sh))
                    
                    # 2. Kirim Request
                    requests = []
                    for _, sh in batch_scripthashes:
                        requests.append(session.send_request('blockchain.scripthash.get_balance', [sh]))
                    
                    # 3. Tunggu Hasil (Timeout 5 detik agar tidak hang)
                    results = await asyncio.wait_for(asyncio.gather(*requests, return_exceptions=True), timeout=10)
                    
                    # 4. Cek Saldo
                    for i, res in enumerate(results):
                        if isinstance(res, dict):
                            bal = res.get('confirmed', 0) + res.get('unconfirmed', 0)
                            if bal > 0:
                                addr = batch_scripthashes[i][0]
                                wif = batch_data[addr]
                                queue.put((addr, wif, bal))
                        
                    # 5. Update Counter
                    with counter.get_lock():
                        counter.value += BATCH_SIZE
                        
        except Exception:
            # Jika error (DNS, Timeout, Putus), diam saja dan langsung ganti server
            # await asyncio.sleep(1)
            continue

def process_entry(queue, counter):
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(worker_logic(queue, counter))
    except KeyboardInterrupt:
        pass

# ========== 3. MAIN UI ==========

def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    hash_mode = "Native" if HASH_PROVIDER == "hashlib" else "PyCryptodome (Safe Mode)"
    print(f"""
    ╔════════════════════════════════════════════════╗
    ║     BITCOIN HUNTER - STABLE EDITION v6         ║
    ╚════════════════════════════════════════════════╝
    [+] Hash Engine  : {hash_mode}
    [+] Workers      : {NUM_PROCESSES}
    [+] Batch Size   : {BATCH_SIZE} wallets/call
    [+] Server List  : {len(ELECTRUM_SERVERS)} Nodes
    """)
    
    result_queue = Queue()
    counter = Value('i', 0)
    
    processes = []
    print(f"🚀 Memulai scanning... (Tunggu beberapa detik untuk koneksi stabil)")
    
    for _ in range(NUM_PROCESSES):
        p = Process(target=process_entry, args=(result_queue, counter))
        p.start()
        processes.append(p)
    
    start_time = time.time()
    
    try:
        while True:
            time.sleep(1)
            elapsed = time.time() - start_time
            total = counter.value
            speed = total / elapsed if elapsed > 0 else 0
            
            sys.stdout.write(
                f"\r[*] Scan: {total:,} | Speed: {speed:.0f} keys/s | Found: {result_queue.qsize()} "
            )
            sys.stdout.flush()
            
            while not result_queue.empty():
                addr, wif, bal = result_queue.get()
                msg = (f"\n\n🚨 JACKPOT FOUND! 🚨\n"
                       f"Address: {addr}\n"
                       f"Private: {wif}\n"
                       f"Balance: {bal} Sats\n"
                       f"{'='*40}\n")
                print(msg)
                with open(RICH_LOG_FILE, "a") as f:
                    f.write(f"ADDR: {addr} | WIF: {wif} | BAL: {bal}\n")
                    
    except KeyboardInterrupt:
        print("\n\n🛑 Stopping...")
        for p in processes:
            p.terminate()

if __name__ == "__main__":
    try:
        import multiprocessing
        multiprocessing.freeze_support()
    except:
        pass
    main()
