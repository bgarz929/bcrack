import os
import sys
import time
import hashlib
import asyncio
import ssl
import random
import logging
from multiprocessing import Process, Queue, cpu_count, Event, Value

# ========== SETUP LOGGING & IMPORT CHECK ==========
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

try:
    import base58
    from ecdsa import SECP256k1, SigningKey
except ImportError:
    print("❌ ERROR: Library kriptografi belum terinstall.")
    print("👉 Jalankan: pip install ecdsa base58")
    sys.exit(1)

try:
    from aiorpcx import connect_rs
except ImportError:
    print("❌ ERROR: Library Electrum belum terinstall.")
    print("👉 Jalankan: pip install aiorpcx")
    sys.exit(1)

# ========== KONFIGURASI ==========
NUM_PROCESSES = max(1, cpu_count() - 1)
BATCH_SIZE = 30           # Dikurangi sedikit agar lebih stabil di koneksi lambat
RICH_LOG_FILE = "found_rich.txt"

# Daftar Server Electrum (Mix Mainnet)
ELECTRUM_SERVERS = [
    ("electrum.blockstream.info", 50002),
    ("electrum.check.zoneminder.com", 50002),
    ("electrum.emzy.de", 50002),
    ("bx.in.th", 50002),
    ("bitcoin.lukechilds.co", 50002),
    ("104.248.139.211", 50002),
    ("electrum.acinq.co", 50002),
]

# ========== 1. KRIPTOGRAFI (KEY GENERATOR) ==========

def generate_key_pair():
    """Generate Private Key, WIF, dan Address (P2PKH)"""
    # 1. Private Key
    priv_bytes = os.urandom(32)
    
    # 2. WIF Compressed
    extended_key = b"\x80" + priv_bytes + b"\x01"
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    wif = base58.b58encode(extended_key + checksum).decode('utf-8')
    
    # 3. Public Key Compressed
    sk = SigningKey.from_string(priv_bytes, curve=SECP256k1)
    vk = sk.verifying_key
    x_str = vk.to_string()[:32]
    y_str = vk.to_string()[32:]
    
    if int.from_bytes(y_str, byteorder='big') % 2 == 0:
        pub_key_bytes = b'\x02' + x_str
    else:
        pub_key_bytes = b'\x03' + x_str
        
    # 4. Address
    sha256_bpk = hashlib.sha256(pub_key_bytes).digest()
    ripemd160_bpk = hashlib.new('ripemd160')
    ripemd160_bpk.update(sha256_bpk)
    ripemd160_digest = ripemd160_bpk.digest()
    
    network_byte = b'\x00' + ripemd160_digest
    checksum_addr = hashlib.sha256(hashlib.sha256(network_byte).digest()).digest()[:4]
    address = base58.b58encode(network_byte + checksum_addr).decode('utf-8')
    
    return wif, address

def address_to_scripthash(address):
    """Convert Address -> ScriptHash untuk Electrum Protocol"""
    try:
        decoded = base58.b58decode_check(address)
        # P2PKH start with 0x00
        if decoded[0] != 0:
            return None
        pubkey_hash = decoded[1:]
        # Script: OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
        script = b'\x76\xa9\x14' + pubkey_hash + b'\x88\xac'
        return hashlib.sha256(script).digest()[::-1].hex()
    except:
        return None

# ========== 2. ELECTRUM CLIENT (ENGINE CEBB.PY) ==========

async def check_balance_batch(session, address_map):
    """
    Kirim request batch ke server Electrum.
    address_map: dict {address: wif}
    Returns: dict {address: balance} (Hanya yg balance > 0)
    """
    found = {}
    
    # Siapkan request
    requests_list = []
    addr_list = []
    
    for addr in address_map:
        sh = address_to_scripthash(addr)
        if sh:
            requests_list.append(session.send_request('blockchain.scripthash.get_balance', [sh]))
            addr_list.append(addr)
    
    if not requests_list:
        return {}

    # Eksekusi Async Parallel
    try:
        results = await asyncio.gather(*requests_list, return_exceptions=True)
        
        for i, res in enumerate(results):
            if isinstance(res, dict):
                # Format: {'confirmed': 123, 'unconfirmed': 0}
                bal = res.get('confirmed', 0) + res.get('unconfirmed', 0)
                if bal > 0:
                    found[addr_list[i]] = bal
            elif isinstance(res, Exception):
                # Ignore individual error
                pass
                
    except Exception as e:
        # Jika koneksi putus di tengah jalan
        pass
        
    return found

async def worker_task(queue, counter, server_info):
    """Task utama worker: Connect -> Generate -> Check Loop"""
    host, port = server_info
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    
    attempt = 0
    while True:
        try:
            # Reconnect loop
            async with connect_rs(host, port, ssl=ssl_ctx) as session:
                if attempt > 0:
                    # Reset attempt jika berhasil connect
                    attempt = 0
                
                # Mining Loop
                while True:
                    # 1. Generate Batch
                    batch_map = {}
                    for _ in range(BATCH_SIZE):
                        wif, addr = generate_key_pair()
                        batch_map[addr] = wif
                    
                    # 2. Check Balance
                    found = await check_balance_batch(session, batch_map)
                    
                    # 3. Handle Found
                    if found:
                        for f_addr, f_bal in found.items():
                            f_wif = batch_map[f_addr]
                            queue.put((f_addr, f_wif, f_bal))
                    
                    # 4. Update Counter
                    with counter.get_lock():
                        counter.value += BATCH_SIZE
                        
        except Exception as e:
            # Error handling & Server Rotation
            attempt += 1
            if attempt % 10 == 0:
                # Jika 10x gagal, print error agar user tahu
                print(f"\n[Worker Warning] Gagal konek ke {host}: {e}. Retrying...")
            await asyncio.sleep(2) # Tunggu sebelum reconnect

def process_entry(queue, counter, server_list):
    """Entry point untuk Multiprocessing"""
    # Pilih server secara acak untuk load balancing
    server = random.choice(server_list)
    
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
    try:
        asyncio.run(worker_task(queue, counter, server))
    except KeyboardInterrupt:
        pass

# ========== 3. MAIN CONTROLLER ==========

def test_connection():
    """Test koneksi internet sebelum mulai"""
    print("⏳ Sedang mengetes koneksi ke Server Electrum...")
    host, port = ELECTRUM_SERVERS[0]
    
    async def run_test():
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        try:
            async with connect_rs(host, port, ssl=ssl_ctx) as session:
                # Cek Address Satoshi (Genesis) sebagai test
                genesis = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
                sh = address_to_scripthash(genesis)
                res = await session.send_request('blockchain.scripthash.get_balance', [sh])
                return res
        except Exception as e:
            return e

    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    result = asyncio.run(run_test())
    
    if isinstance(result, dict):
        print(f"✅ Koneksi BERHASIL! Server merespon. (Test Balance: {result})")
        return True
    else:
        print(f"❌ KONEKSI GAGAL: {result}")
        print("⚠️  Pastikan internet stabil. Script mungkin tidak jalan semestinya.")
        return False

def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"""
    ╔════════════════════════════════════════════════╗
    ║     BITCOIN HUNTER x ELECTRUM (STABLE v4)      ║
    ╚════════════════════════════════════════════════╝
    [+] Cores: {cpu_count()} | Workers: {NUM_PROCESSES}
    [+] Batch: {BATCH_SIZE} wallets/call
    """)
    
    if not test_connection():
        q = input("Ingin tetap lanjut? (y/n): ")
        if q.lower() != 'y':
            sys.exit()

    result_queue = Queue()
    counter = Value('i', 0)
    
    processes = []
    print(f"\n🚀 Memulai {NUM_PROCESSES} worker... Tekan CTRL+C untuk stop.")
    
    for _ in range(NUM_PROCESSES):
        p = Process(target=process_entry, args=(result_queue, counter, ELECTRUM_SERVERS))
        p.start()
        processes.append(p)
    
    start_time = time.time()
    
    try:
        while True:
            time.sleep(1)
            elapsed = time.time() - start_time
            total = counter.value
            speed = total / elapsed if elapsed > 0 else 0
            
            # Tampilan Status Bar
            sys.stdout.write(
                f"\r[*] Total Scan: {total:,} | Speed: {speed:.0f} keys/s | Found: {result_queue.qsize()} "
            )
            sys.stdout.flush()
            
            # Cek Hasil
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
