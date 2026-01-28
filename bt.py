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

# ========== 1. CEK DEPENDENCIES & HASH FIX ==========
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
BATCH_SIZE = 40  
RICH_LOG_FILE = "found_rich.txt"

# Server Electrum Stabil
ELECTRUM_SERVERS = [
    ("electrum.blockstream.info", 50002),
    ("electrum.emzy.de", 50002),
    ("bitcoin.lukechilds.co", 50002),
    ("electrum.bitaroo.net", 50002),
    ("ssl.mercurywallet.com", 50002),
]

# Daftar Alamat Test (Untuk memastikan Server berfungsi)
TEST_ADDRESSES = [
    "12tkqA9xSoowkzoERHMWNKsTey55YEBqkv",
    "1PeizMg76Cf96nUQrYg8xuoZWLQozU5zGW",
    "1f1miYFQWTzdLiCBxtHHnNiW7WAWPUccr",
    "1BAFWQhH9pNkz3mZDQ1tWrtKkSHVCkc3fV",
    "14YK4mzJGo5NKkNnmVJeuEAQftLt795Gec",
    "1KbrSKrT3GeEruTuuYYUSQ35JwKbrAWJYm"
]

# ========== 2. FUNGSI KONVERSI ==========

def address_to_scripthash(address):
    try:
        decoded = base58.b58decode_check(address)
        if decoded[0] != 0: return None 
        script = b'\x76\xa9\x14' + decoded[1:] + b'\x88\xac'
        return hashlib.sha256(script).digest()[::-1].hex()
    except: return None

def generate_key_pair():
    priv_bytes = os.urandom(32)
    extended_key = b"\x80" + priv_bytes + b"\x01"
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    wif = base58.b58encode(extended_key + checksum).decode('utf-8')
    
    sk = SigningKey.from_string(priv_bytes, curve=SECP256k1)
    vk = sk.verifying_key
    
    x_str = vk.to_string()[:32]
    y_str = vk.to_string()[32:]
    pub_key_bytes = (b'\x02' if int.from_bytes(y_str, 'big') % 2 == 0 else b'\x03') + x_str
        
    sha256_bpk = hashlib.sha256(pub_key_bytes).digest()
    ripemd160_digest = calc_ripemd160(sha256_bpk)
    
    network_byte = b'\x00' + ripemd160_digest
    checksum_addr = hashlib.sha256(hashlib.sha256(network_byte).digest()).digest()[:4]
    address = base58.b58encode(network_byte + checksum_addr).decode('utf-8')
    
    return wif, address

# ========== 3. FITUR STARTUP SELF-TEST (BARU) ==========

async def run_startup_test():
    """Fungsi ini berjalan SATU KALI di awal untuk cek koneksi & akurasi"""
    print("\n🔍 MELAKUKAN SELF-DIAGNOSTIC (CEK SERVER & SALDO VALID)...")
    print("="*80)
    
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    
    # Coba konek ke salah satu server
    connected = False
    for server in ELECTRUM_SERVERS:
        host, port = server
        try:
            print(f"⌛ Menghubungkan ke {host}...", end="\r")
            async with connect_rs(host, port, ssl=ssl_ctx) as session:
                print(f"✅ Terhubung ke {host} [OK]                  ")
                print("-" * 80)
                
                # Test Semua Alamat dalam Daftar
                for addr in TEST_ADDRESSES:
                    sh = address_to_scripthash(addr)
                    if not sh:
                        print(f"❌ Invalid Address format: {addr}")
                        continue
                        
                    # Request Saldo Real
                    res = await session.send_request('blockchain.scripthash.get_balance', [sh])
                    
                    bal_conf = res.get('confirmed', 0)
                    bal_unconf = res.get('unconfirmed', 0)
                    total_bal = bal_conf + bal_unconf
                    
                    # Convert ke BTC untuk display enak dilihat
                    btc_bal = total_bal / 100000000
                    
                    status = "✅ PASS" if total_bal >= 0 else "❌ FAIL"
                    print(f"[{status}] {addr[:15]}... | Balance: {total_bal:>16,} Sats ({btc_bal:.4f} BTC)")
                
                connected = True
                break # Jika satu server berhasil, stop loop server
        except Exception as e:
            print(f"⚠️  Gagal ke {host}: {str(e)}")
            continue
            
    print("="*80)
    if not connected:
        print("❌ SEMUA KONEKSI SERVER GAGAL. PERIKSA INTERNET ANDA!")
        sys.exit(1)
    else:
        print("🚀 DIAGNOSTIK SELESAI. SISTEM SIAP. MEMULAI BRUTEFORCE DALAM 3 DETIK...")
        time.sleep(3)

# ========== 4. WORKER LOGIC (MATRIX MODE) ==========

async def worker_logic(queue, counter, display_queue):
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
                    last_sample = None

                    for _ in range(BATCH_SIZE):
                        wif, addr = generate_key_pair()
                        sh = address_to_scripthash(addr)
                        if sh:
                            batch_data[addr] = wif
                            batch_scripthashes.append((addr, sh))
                            last_sample = (addr, wif)
                    
                    requests = []
                    for _, sh in batch_scripthashes:
                        requests.append(session.send_request('blockchain.scripthash.get_balance', [sh]))
                    
                    results = await asyncio.wait_for(asyncio.gather(*requests, return_exceptions=True), timeout=10)
                    
                    # Stream log
                    if last_sample and not display_queue.full():
                         try:
                             display_queue.put_nowait((last_sample[0], last_sample[1], 0))
                         except: pass

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

def process_entry(queue, counter, display_queue):
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(worker_logic(queue, counter, display_queue))
    except KeyboardInterrupt:
        pass

# ========== 5. MAIN PROGRAM ==========

def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"""
    ╔═════════════════════════════════════════════════════════╗
    ║        BITCOIN HUNTER - DIAGNOSTIC & MATRIX v10         ║
    ╚═════════════════════════════════════════════════════════╝
    """)
    
    # --- JALANKAN TEST PENGECEKAN BALANCE DULU ---
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(run_startup_test())
    # ---------------------------------------------
    
    print(f"{'STATUS':<10} | {'ADDRESS':<34} | {'PRIVATE KEY (WIF)':<52}")
    print("="*100)
    
    result_queue = Queue()
    display_queue = Queue(maxsize=100) 
    counter = Value('i', 0)
    
    processes = []
    
    for _ in range(NUM_PROCESSES):
        p = Process(target=process_entry, args=(result_queue, counter, display_queue))
        p.start()
        processes.append(p)
    
    start_time = time.time()
    
    try:
        while True:
            try:
                for _ in range(20): 
                    if not display_queue.empty():
                        d_addr, d_wif, d_bal = display_queue.get_nowait()
                        print(f"[{d_bal} SATS]  | {d_addr:<34} | {d_wif}")
            except Exception:
                pass
            
            while not result_queue.empty():
                addr, wif, bal = result_queue.get()
                print("\n" + "█"*100)
                print(f"🚨 JACKPOT FOUND! 🚨")
                print(f"💰 BALANCE : {bal} SATS")
                print(f"🏠 ADDRESS : {addr}")
                print(f"🔑 PRIVATE : {wif}")
                print("█"*100 + "\n")
                
                with open(RICH_LOG_FILE, "a") as f:
                    f.write(f"ADDR: {addr} | WIF: {wif} | BAL: {bal}\n")
            
            time.sleep(0.01)
                    
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
