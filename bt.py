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

# Coba import library dari cebb.py
try:
    from aiorpcx import connect_rs
except ImportError:
    print("❌ Library 'aiorpcx' belum diinstall.")
    print("👉 Jalankan: pip install aiorpcx")
    sys.exit(1)

# ========== KONFIGURASI ==========
NUM_PROCESSES = max(1, cpu_count() - 1)
BATCH_SIZE = 50  # Sekali kirim cek 50 wallet (Efisien)
RICH_LOG_FILE = "found_rich.txt"

# ========== DAFTAR SERVER (Dari standar cebb.py/Electrum) ==========
# Server ini adalah server 'Tier 1' yang digunakan cebb.py untuk koneksi stabil.
ELECTRUM_SERVERS = [
    ("electrum.blockstream.info", 50002),
    ("electrum.emzy.de", 50002),
    ("bitcoin.lukechilds.co", 50002),
    ("electrum.bitaroo.net", 50002),
    ("ssl.mercurywallet.com", 50002),
]

# ========== 1. GENERATOR (Dari bck.py) ==========

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
        
    # Address P2PKH
    sha256_bpk = hashlib.sha256(pub_key_bytes).digest()
    ripemd160_bpk = hashlib.new('ripemd160')
    ripemd160_bpk.update(sha256_bpk)
    ripemd160_digest = ripemd160_bpk.digest()
    
    network_byte = b'\x00' + ripemd160_digest
    checksum_addr = hashlib.sha256(hashlib.sha256(network_byte).digest()).digest()[:4]
    address = base58.b58encode(network_byte + checksum_addr).decode('utf-8')
    
    return wif, address

# ========== 2. FUNGSI ELECTRUM (Dari cebb.py) ==========

def address_to_scripthash(address):
    """
    FUNGSI KRUSIAL DARI CEBB.PY
    Electrum tidak mengecek address, tapi mengecek 'scripthash'.
    Kita harus convert Address -> Script -> SHA256 -> Reverse Hex.
    """
    try:
        decoded = base58.b58decode_check(address)
        if decoded[0] != 0: 
            return None # Hanya support P2PKH (Address awalan 1)
        pubkey_hash = decoded[1:]
        
        # Script P2PKH: OP_DUP OP_HASH160 <PUBKEY> OP_EQUALVERIFY OP_CHECKSIG
        script = b'\x76\xa9\x14' + pubkey_hash + b'\x88\xac'
        
        # Hash SHA256 dari script
        h = hashlib.sha256(script).digest()
        
        # Reverse byte order (Endianness) lalu hex
        return h[::-1].hex()
    except:
        return None

async def worker_logic(queue, counter, server_host, server_port):
    """Logika utama worker menggunakan connect_rs aiorpcx"""
    
    # SSL Context persis seperti cebb.py (mengabaikan sertifikat self-signed)
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    print(f"🔗 Menghubungkan ke {server_host}...")

    while True:
        try:
            # Membuka koneksi TCP SSL
            async with connect_rs(server_host, server_port, ssl=ssl_ctx) as session:
                print(f"✅ Terhubung ke {server_host}. Mining dimulai!")
                
                while True:
                    # 1. Generate Batch Keys
                    batch_data = {} # {address: wif}
                    batch_scripthashes = []
                    
                    for _ in range(BATCH_SIZE):
                        wif, addr = generate_key_pair()
                        sh = address_to_scripthash(addr)
                        if sh:
                            batch_data[addr] = wif
                            batch_scripthashes.append((addr, sh))
                    
                    # 2. Siapkan Request Electrum (blockchain.scripthash.get_balance)
                    requests = []
                    for _, sh in batch_scripthashes:
                        requests.append(session.send_request('blockchain.scripthash.get_balance', [sh]))
                    
                    # 3. Kirim Request & Tunggu (Await)
                    # Menggunakan gather untuk mengirim semua request sekaligus (Parallel check)
                    results = await asyncio.gather(*requests, return_exceptions=True)
                    
                    # 4. Cek Hasil
                    for i, res in enumerate(results):
                        if isinstance(res, dict):
                            # Format response: {'confirmed': 0, 'unconfirmed': 0}
                            balance = res.get('confirmed', 0) + res.get('unconfirmed', 0)
                            
                            if balance > 0:
                                addr = batch_scripthashes[i][0]
                                wif = batch_data[addr]
                                queue.put((addr, wif, balance))
                        elif isinstance(res, Exception):
                            # Jika error spesifik, abaikan saja untuk address ini
                            pass

                    # 5. Update Counter UI
                    with counter.get_lock():
                        counter.value += BATCH_SIZE
                        
        except Exception as e:
            # Jika koneksi putus, print error kecil dan retry loop luar
            print(f"⚠️ Koneksi {server_host} terputus: {e}. Reconnecting in 3s...")
            await asyncio.sleep(3)

def process_entry(queue, counter):
    """Entry point untuk Multiprocessing"""
    # Pilih server secara acak untuk load balancing
    server = random.choice(ELECTRUM_SERVERS)
    
    # Fix untuk Windows Event Loop
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
    try:
        asyncio.run(worker_logic(queue, counter, server[0], server[1]))
    except KeyboardInterrupt:
        pass

# ========== 3. MAIN UI ==========

def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"""
    ╔════════════════════════════════════════════════╗
    ║    BITCOIN HUNTER x CEBB ENGINE (FUSION)       ║
    ╚════════════════════════════════════════════════╝
    [+] Method       : aiorpcx + SSL (Metode cebb.py)
    [+] Server List  : Blockstream & Top Tier Nodes
    [+] Workers      : {NUM_PROCESSES}
    [+] Batch Size   : {BATCH_SIZE} wallets/call
    """)
    
    result_queue = Queue()
    counter = Value('i', 0)
    
    processes = []
    print(f"🚀 Memulai {NUM_PROCESSES} worker...")
    
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
            
            # Tampilan Status Bar
            sys.stdout.write(
                f"\r[*] Scan: {total:,} | Speed: {speed:.0f} keys/s | Found: {result_queue.qsize()} "
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
