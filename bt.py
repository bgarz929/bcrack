import os
import sys
import time
import hashlib
import asyncio
import ssl
import random
import base58
from multiprocessing import Process, Queue, cpu_count, Event, Value
from ecdsa import SECP256k1, SigningKey
from aiorpcx import connect_rs

# ========== KONFIGURASI ==========
NUM_PROCESSES = max(1, cpu_count() - 1)
BATCH_SIZE = 50  # Jumlah wallet yang dicek dalam sekali request (Efisiensi Electrum)
RICH_LOG_FILE = "found_rich.txt"

# ========== 1. MODUL KRIPTOGRAFI (Dari bck.py) ==========

def generate_key_pair():
    """Generate Private Key, WIF, dan Address sekaligus"""
    # 1. Private Key
    priv_bytes = os.urandom(32)
    priv_hex = priv_bytes.hex()
    
    # 2. WIF (Compressed)
    extended_key = b"\x80" + priv_bytes + b"\x01"
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    wif = base58.b58encode(extended_key + checksum).decode('utf-8')
    
    # 3. Public Key (Compressed)
    sk = SigningKey.from_string(priv_bytes, curve=SECP256k1)
    vk = sk.verifying_key
    x_str = vk.to_string()[:32]
    y_str = vk.to_string()[32:]
    
    if int.from_bytes(y_str, byteorder='big') % 2 == 0:
        pub_key_bytes = b'\x02' + x_str
    else:
        pub_key_bytes = b'\x03' + x_str
        
    # 4. Address P2PKH
    sha256_bpk = hashlib.sha256(pub_key_bytes).digest()
    ripemd160_bpk = hashlib.new('ripemd160')
    ripemd160_bpk.update(sha256_bpk)
    ripemd160_digest = ripemd160_bpk.digest()
    
    network_byte = b'\x00' + ripemd160_digest
    checksum_addr = hashlib.sha256(hashlib.sha256(network_byte).digest()).digest()[:4]
    address = base58.b58encode(network_byte + checksum_addr).decode('utf-8')
    
    return priv_hex, wif, address

# ========== 2. MODUL ELECTRUM (Dari cebb.py) ==========

def address_to_scripthash(address):
    """Mengubah address menjadi scripthash untuk query Electrum"""
    try:
        decoded = base58.b58decode_check(address)
        ver, payload = decoded[0], decoded[1:]
        if ver == 0x00:  # P2PKH
            script = b"\x76\xa9\x14" + payload + b"\x88\xac"
        elif ver == 0x05: # P2SH
            script = b"\xa9\x14" + payload + b"\x87"
        else:
            return None
        return hashlib.sha256(script).digest()[::-1].hex()
    except Exception:
        return None

class FastElectrumServerManager:
    """Manajemen koneksi server Electrum (Diambil dari cebb.py)"""
    def __init__(self):
        self.servers = [
            {"host": "blockitall.us", "port": 50002},
            {"host": "electrum.loyce.club", "port": 50002},
            {"host": "electrum.cakewallet.com", "port": 50002},
            {"host": "electrum.blockstream.info", "port": 50002},
            {"host": "btc.electroncash.dk", "port": 60002},
        ]
        self._ssl_context = ssl.create_default_context()
        self._ssl_context.check_hostname = False
        self._ssl_context.verify_mode = ssl.CERT_NONE

    def get_random_server(self):
        return random.choice(self.servers)

class FastElectrumClient:
    """Client Async untuk cek balance (Versi ringan dari cebb.py)"""
    def __init__(self, server_manager):
        self.manager = server_manager

    async def get_balance_batch(self, addresses_map):
        """
        Cek balance banyak address sekaligus dalam satu koneksi.
        addresses_map: Dict {address: wif}
        """
        results = {}
        server = self.manager.get_random_server()
        
        try:
            async with connect_rs(server["host"], server["port"], ssl=self.manager._ssl_context) as session:
                # Kirim request secara parallel (gather)
                tasks = []
                addr_list = list(addresses_map.keys())
                
                for addr in addr_list:
                    scripthash = address_to_scripthash(addr)
                    if scripthash:
                        # Request Electrum: blockchain.scripthash.get_balance
                        tasks.append(session.send_request("blockchain.scripthash.get_balance", [scripthash]))
                    else:
                        tasks.append(None) # Invalid address handling

                # Tunggu semua jawaban
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                
                for i, resp in enumerate(responses):
                    if isinstance(resp, dict):
                        # Electrum response: {'confirmed': 0, 'unconfirmed': 0}
                        total = resp.get("confirmed", 0) + resp.get("unconfirmed", 0)
                        if total > 0:
                            addr = addr_list[i]
                            results[addr] = total
        except Exception:
            # Jika server error, return kosong (akan diskip batch ini, atau bisa diretry)
            pass
            
        return results

# ========== 3. WORKER LOGIC (Digabungkan) ==========

async def async_worker_loop(queue, found_event, counter):
    """Loop utama worker dalam mode Async"""
    server_manager = FastElectrumServerManager()
    client = FastElectrumClient(server_manager)
    
    while not found_event.is_set():
        try:
            # 1. Generate Batch Addresses
            # Kita generate BATCH_SIZE (misal 50) sekaligus
            batch_data = {} # {address: wif}
            
            for _ in range(BATCH_SIZE):
                priv, wif, addr = generate_key_pair()
                batch_data[addr] = wif
            
            # 2. Cek Balance via Electrum (Cepat!)
            # Ini menggantikan check_balance() lama yang satu-satu
            found_balances = await client.get_balance_batch(batch_data)
            
            # 3. Proses Hasil
            with counter.get_lock():
                counter.value += BATCH_SIZE
                
            for addr, balance in found_balances.items():
                if balance > 0:
                    wif = batch_data[addr]
                    result = {
                        "type": "RICH",
                        "address": addr,
                        "wif": wif,
                        "balance": balance
                    }
                    queue.put(result)
                    found_event.set() # Stop semua jika ketemu (opsional)

        except Exception as e:
            await asyncio.sleep(1) # Tunggu sebentar jika error network
            continue

def worker_wrapper(queue, found_event, counter):
    """Wrapper untuk menjalankan Asyncio di dalam Multiprocessing"""
    # Windows fix untuk event loop policy
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
    asyncio.run(async_worker_loop(queue, found_event, counter))

# ========== 4. MAIN MONITOR ==========

def print_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"""
    ╔══════════════════════════════════════════════════════════╗
    ║        BITCOIN HUNTER x ELECTRUM UPGRADED v5.0           ║
    ║      Engine: Async Electrum Protocol (TCP/SSL)           ║
    ╚══════════════════════════════════════════════════════════╝
    [+] Cores        : {cpu_count()}
    [+] Workers      : {NUM_PROCESSES}
    [+] Batch Size   : {BATCH_SIZE} wallets/request
    [+] Output       : {RICH_LOG_FILE}
    """)

def main():
    print_banner()
    
    result_queue = Queue()
    found_event = Event()
    counter = Value('i', 0)
    
    processes = []
    for _ in range(NUM_PROCESSES):
        p = Process(target=worker_wrapper, args=(result_queue, found_event, counter))
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
                f"\r[*] Scan: {total:,} Keys | Speed: {speed:.2f} Keys/s | Found: {result_queue.qsize()} "
            )
            sys.stdout.flush()
            
            while not result_queue.empty():
                data = result_queue.get()
                msg = (f"\n\n[!!!] JACKPOT FOUND [!!!]\n"
                       f"Address: {data['address']}\n"
                       f"WIF    : {data['wif']}\n"
                       f"Balance: {data['balance']} Sats\n"
                       f"{'-'*40}\n")
                print(msg)
                with open(RICH_LOG_FILE, "a") as f:
                    f.write(f"Address: {data['address']} | WIF: {data['wif']} | Bal: {data['balance']}\n")
                    
    except KeyboardInterrupt:
        print("\nStopping...")
        found_event.set()
        for p in processes:
            p.terminate()

if __name__ == "__main__":
    try:
        import multiprocessing
        multiprocessing.freeze_support()
    except:
        pass
    main()
