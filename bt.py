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
logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(message)s')

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
BATCH_SIZE = 40           
RICH_LOG_FILE = "found_rich.txt"

# [UPDATE] DAFTAR SERVER YANG PASTI HIDUP (2025)
# Kita hanya pakai server SSL (Port 50002) yang stabil
ELECTRUM_SERVERS = [
    ("electrum.blockstream.info", 50002),
    ("electrum.emzy.de", 50002),
    ("bitcoin.lukechilds.co", 50002),
    ("electrum.acinq.co", 50002),
    ("ssl.mercurywallet.com", 50002),
    ("electrum.bitaroo.net", 50002),
    ("electrum.jochen-hoenicke.de", 50002),
    ("fortress.qtornado.com", 50002),
]

# ========== 1. KRIPTOGRAFI (OPTIMIZED) ==========

def generate_key_pair():
    """Generate Private Key, WIF, dan Address (P2PKH)"""
    priv_bytes = os.urandom(32)
    
    # WIF Compressed
    extended_key = b"\x80" + priv_bytes + b"\x01"
    first_sha = hashlib.sha256(extended_key).digest()
    checksum = hashlib.sha256(first_sha).digest()[:4]
    wif = base58.b58encode(extended_key + checksum).decode('utf-8')
    
    # Public Key Compressed
    sk = SigningKey.from_string(priv_bytes, curve=SECP256k1)
    vk = sk.verifying_key
    x_str = vk.to_string()[:32]
    y_str = vk.to_string()[32:]
    
    if int.from_bytes(y_str, byteorder='big') % 2 == 0:
        pub_key_bytes = b'\x02' + x_str
    else:
        pub_key_bytes = b'\x03' + x_str
        
    # Address P2PKH
    sha256_bpk = hashlib.sha256(pub_key_bytes).digest()
    ripemd160_bpk = hashlib.new('ripemd160')
    ripemd160_bpk.update(sha256_bpk)
    ripemd160_digest = ripemd160_bpk.digest()
    
    network_byte = b'\x00' + ripemd160_digest
    checksum_addr = hashlib.sha256(hashlib.sha256(network_byte).digest()).digest()[:4]
    address = base58.b58encode(network_byte + checksum_addr).decode('utf-8')
    
    return wif, address

def address_to_scripthash(address):
    try:
        decoded = base58.b58decode_check(address)
        if decoded[0] != 0: return None
        pubkey_hash = decoded[1:]
        script = b'\x76\xa9\x14' + pubkey_hash + b'\x88\xac'
        return hashlib.sha256(script).digest()[::-1].hex()
    except:
        return None

# ========== 2. ELECTRUM ENGINE (AUTO-SWITCH) ==========

async def check_balance_batch(session, address_map):
    found = {}
    requests_list = []
    addr_list = []
    
    for addr in address_map:
        sh = address_to_scripthash(addr)
        if sh:
            requests_list.append(session.send_request('blockchain.scripthash.get_balance', [sh]))
            addr_list.append(addr)
    
    if not requests_list: return {}

    try:
        # Timeout per batch request (3 detik maks per batch)
        results = await asyncio.wait_for(asyncio.gather(*requests_list, return_exceptions=True), timeout=5)
        
        for i, res in enumerate(results):
            if isinstance(res, dict):
                bal = res.get('confirmed', 0) + res.get('unconfirmed', 0)
                if bal > 0:
                    found[addr_list[i]] = bal
    except Exception:
        # Jika timeout/error, biarkan kosong, worker akan lanjut/ganti server
        pass
        
    return found

async def worker_task(queue, counter):
    """Worker yang pintar berpindah server jika gagal"""
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    
    while True:
        # 1. PILIH SERVER ACAK
        server = random.choice(ELECTRUM_SERVERS)
        host, port = server
        
        try:
            # 2. COBA KONEK (Timeout 5 detik)
            # Jika server mati, dia langsung throw error dan pindah ke loop berikutnya (server lain)
            async with connect_rs(host, port, ssl=ssl_ctx) as session:
                
                # Jika berhasil konek, masuk mode mining
                # print(f"[DEBUG] Terhubung ke {host}") # Uncomment jika ingin lihat koneksi
                
                while True:
                    # A. Generate
                    batch_map = {}
                    for _ in range(BATCH_SIZE):
                        wif, addr = generate_key_pair()
                        batch_map[addr] = wif
                    
                    # B. Check
                    found = await check_balance_batch(session, batch_map)
                    
                    # C. Save
                    if found:
                        for f_addr, f_bal in found.items():
                            queue.put((f_addr, batch_map[f_addr], f_bal))
                    
                    # D. Update Speed
                    with counter.get_lock():
                        counter.value += BATCH_SIZE
                        
        except Exception:
            # Jika error koneksi, diam saja dan langsung loop ulang pilih server lain
            # await asyncio.sleep(0.5) 
            continue

def process_entry(queue, counter):
    """Wrapper untuk Windows/Multiprocessing"""
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    try:
        asyncio.run(worker_task(queue, counter))
    except KeyboardInterrupt:
        pass

# ========== 3. MAIN UI ==========

def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"""
    ╔════════════════════════════════════════════════╗
    ║      BITCOIN HUNTER v5 (SMART SWITCH)          ║
    ╚════════════════════════════════════════════════╝
    [+] Server List  : {len(ELECTRUM_SERVERS)} High-Speed Nodes
    [+] Workers      : {NUM_PROCESSES}
    [+] Batch Size   : {BATCH_SIZE}
    """)
    
    # Test koneksi internet dasar (Google DNS)
    # untuk memastikan masalah bukan di modem user
    try:
        import socket
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        print("✅ Internet Online.")
    except OSError:
        print("❌ Internet OFFLINE. Periksa koneksi data/wifi Anda.")
        sys.exit()

    result_queue = Queue()
    counter = Value('i', 0)
    
    processes = []
    print(f"\n🚀 Memulai scanning... (Tunggu ~10 detik untuk warm-up)")
    
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
            
            # Tampilan satu baris yang bersih
            sys.stdout.write(
                f"\r[*] Scan: {total:,} keys | Speed: {speed:.0f} keys/s | Found: {result_queue.qsize()} "
            )
            sys.stdout.flush()
            
            # Cek Hasil
            while not result_queue.empty():
                addr, wif, bal = result_queue.get()
                print(f"\n\n🚨 FOUND! {addr} | Bal: {bal}\n")
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
