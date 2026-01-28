import os
import sys
import time
import hashlib
import asyncio
import ssl
import random
import logging
import base58
from multiprocessing import Process, Queue, cpu_count, Value
from ecdsa import SECP256k1, SigningKey

# ========== 1. CEK DEPENDENCIES & HASH FIX (RIPEMD160) ==========
def get_ripemd160_hasher():
    try:
        hashlib.new('ripemd160')
        return "hashlib"
    except ValueError:
        try:
            from Crypto.Hash import RIPEMD160
            return "pycryptodome"
        except ImportError:
            print("\n❌ CRITICAL ERROR: Butuh library pycryptodome.")
            print("👉 pip install pycryptodome\n")
            sys.exit(1)

HASH_PROVIDER = get_ripemd160_hasher()

def calc_ripemd160(data_bytes):
    if HASH_PROVIDER == "hashlib":
        h = hashlib.new('ripemd160')
        h.update(data_bytes)
        return h.digest()
    else:
        from Crypto.Hash import RIPEMD160
        h = RIPEMD160.new()
        h.update(data_bytes)
        return h.digest()

try:
    from aiorpcx import connect_rs
except ImportError:
    print("❌ Error: pip install aiorpcx")
    sys.exit(1)

# ========== KONFIGURASI ==========
NUM_PROCESSES = max(1, cpu_count() - 1)
BATCH_SIZE = 50 
RICH_LOG_FILE = "found_rich.txt"

# Server Electrum Stabil
ELECTRUM_SERVERS = [
    ("electrum.blockstream.info", 50002),
    ("electrum.emzy.de", 50002),
    ("bitcoin.lukechilds.co", 50002),
    ("electrum.bitaroo.net", 50002),
    ("ssl.mercurywallet.com", 50002),
    ("electrum.jochen-hoenicke.de", 50002),
]

# ========== 2. GENERATOR KEY ==========

def generate_key_pair():
    priv_bytes = os.urandom(32)
    extended_key = b"\x80" + priv_bytes + b"\x01"
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    wif = base58.b58encode(extended_key + checksum).decode('utf-8')
    
    sk = SigningKey.from_string(priv_bytes, curve=SECP256k1)
    vk = sk.verifying_key
    
    # Compress PubKey Logic
    x_str = vk.to_string()[:32]
    y_str = vk.to_string()[32:]
    pub_key_bytes = (b'\x02' if int.from_bytes(y_str, 'big') % 2 == 0 else b'\x03') + x_str
        
    sha256_bpk = hashlib.sha256(pub_key_bytes).digest()
    ripemd160_digest = calc_ripemd160(sha256_bpk)
    
    network_byte = b'\x00' + ripemd160_digest
    checksum_addr = hashlib.sha256(hashlib.sha256(network_byte).digest()).digest()[:4]
    address = base58.b58encode(network_byte + checksum_addr).decode('utf-8')
    
    return wif, address

# ========== 3. ENGINE ELECTRUM ==========

def address_to_scripthash(address):
    try:
        decoded = base58.b58decode_check(address)
        if decoded[0] != 0: return None 
        script = b'\x76\xa9\x14' + decoded[1:] + b'\x88\xac'
        return hashlib.sha256(script).digest()[::-1].hex()
    except: return None

async def worker_logic(queue, counter, monitor_queue):
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    while True:
        server = random.choice(ELECTRUM_SERVERS)
        host, port = server

        try:
            async with connect_rs(host, port, ssl=ssl_ctx) as session:
                while True:
                    batch_data = {} 
                    batch_scripthashes = []
                    last_wif, last_addr = "", ""

                    for _ in range(BATCH_SIZE):
                        wif, addr = generate_key_pair()
                        sh = address_to_scripthash(addr)
                        if sh:
                            batch_data[addr] = wif
                            batch_scripthashes.append((addr, sh))
                            last_wif, last_addr = wif, addr
                    
                    # --- FITUR VISUAL ---
                    if not monitor_queue.full():
                        try:
                            monitor_queue.put_nowait((last_addr, last_wif))
                        except: pass
                    # --------------------

                    requests = []
                    for _, sh in batch_scripthashes:
                        requests.append(session.send_request('blockchain.scripthash.get_balance', [sh]))
                    
                    results = await asyncio.wait_for(asyncio.gather(*requests, return_exceptions=True), timeout=10)
                    
                    for i, res in enumerate(results):
                        if isinstance(res, dict):
                            bal = res.get('confirmed', 0) + res.get('unconfirmed', 0)
                            if bal > 0:
                                addr = batch_scripthashes[i][0]
                                queue.put((addr, batch_data[addr], bal))
                        
                    with counter.get_lock():
                        counter.value += BATCH_SIZE
                        
        except Exception:
            continue

def process_entry(queue, counter, monitor_queue):
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(worker_logic(queue, counter, monitor_queue))
    except KeyboardInterrupt:
        pass

# ========== 4. MAIN UI (FULL DISPLAY MODE) ==========

def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"""
    ╔════════════════════════════════════════════════╗
    ║     BITCOIN HUNTER - FULL DISPLAY v8           ║
    ╚════════════════════════════════════════════════╝
    [+] Workers      : {NUM_PROCESSES}
    [+] Mode         : FULL WIF DISPLAY (No Truncate)
    """)
    
    result_queue = Queue()
    monitor_queue = Queue(maxsize=1) 
    counter = Value('i', 0)
    
    processes = []
    print(f"🚀 Memulai scanning... (Tunggu data muncul)")
    
    for _ in range(NUM_PROCESSES):
        p = Process(target=process_entry, args=(result_queue, counter, monitor_queue))
        p.start()
        processes.append(p)
    
    start_time = time.time()
    current_display_addr = "Init..."
    current_display_wif = "Init..."
    
    try:
        while True:
            time.sleep(0.1) # Refresh rate
            
            elapsed = time.time() - start_time
            total = counter.value
            speed = total / elapsed if elapsed > 0 else 0
            
            try:
                while not monitor_queue.empty():
                    current_display_addr, current_display_wif = monitor_queue.get_nowait()
            except:
                pass

            # --- BAGIAN INI TIDAK DIPOTONG LAGI ---
            # Kita tampilkan Address dan WIF secara penuh
            d_addr = current_display_addr
            d_wif = current_display_wif 
            
            # Format output panjang
            # \033[K membersihkan sisa baris
            status = f"\r[*] Scan: {total:,} | {d_addr} -> {d_wif} \033[K"
            sys.stdout.write(status)
            sys.stdout.flush()
            
            # Cek Jackpot
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
