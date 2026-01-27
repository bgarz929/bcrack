import os
import sys
import time
import random
import threading
import hashlib
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from binascii import hexlify, unhexlify
from struct import Struct
import asyncio
import base58
import bech32
import ssl
from aiorpcx import connect_rs
import socket

from utils import g, b58encode

# ========== KONFIGURASI ==========
MAX_THREADS = 8                     # Thread untuk wallet generation
BATCH_SIZE = 500                    # Batch lebih kecil untuk feedback lebih cepat
CHECK_BALANCE = True               # Aktifkan pengecekan balance
SAVE_INTERVAL = 500                # Simpan progress lebih sering
MAX_RETRIES = 1                    # Retry untuk koneksi
CONNECTION_TIMEOUT = 3             # Timeout lebih pendek
BALANCE_TIMEOUT = 4                # Timeout untuk balance check
USE_BALANCE_POOL = True            # Gunakan pool untuk balance checking
BALANCE_POOL_SIZE = 4              # Thread khusus untuk balance check

# ========== INISIALISASI ==========
PACKER = Struct(">QQQQ")
file_lock = threading.Lock()
print_lock = threading.Lock()

# File output
WALLETS_FILE = "wallets.txt"
RICH_WALLETS_FILE = "rich_wallets.txt"
LOG_FILE = "scan.log"
PROGRESS_FILE = "progress.txt"

# ========== ELECTRUM SERVER LIST (WORKING SERVERS) ==========
ELECTRUM_SERVERS = [
    {"host": "electrum.emzy.de", "port": 50002},  # Server yang lebih reliable
    {"host": "electrum.blockstream.info", "port": 50002},
    {"host": "electrum.loyce.club", "port": 50002},
    {"host": "bitcoin.aranguren.org", "port": 50002},
]

# ========== GLOBAL STATE ==========
healthy_servers = []
server_cache_lock = threading.Lock()
last_health_check = 0
HEALTH_CHECK_INTERVAL = 600  # 10 menit
balance_pool = None
main_event_loop = None
event_loop_thread = None

# ========== FUNGSI UTILITAS ==========
def log_message(message, level="INFO"):
    """Log pesan ke file dan console"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line = f"[{timestamp}] [{level}] {message}"
    
    with print_lock:
        print(log_line)
    
    with file_lock:
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(log_line + "\n")
        except:
            pass

def save_progress(count, start_time):
    """Simpan progress ke file"""
    try:
        with open(PROGRESS_FILE, "w") as f:
            f.write(f"wallets_generated={count}\n")
            f.write(f"start_time={start_time}\n")
            f.write(f"last_update={time.time()}\n")
    except:
        pass

def load_progress():
    """Load progress dari file"""
    try:
        if os.path.exists(PROGRESS_FILE):
            with open(PROGRESS_FILE, "r") as f:
                lines = f.readlines()
                for line in lines:
                    if "wallets_generated" in line:
                        count = int(line.split("=")[1].strip())
                        return count
    except:
        pass
    return 0

def count_leading_zeroes(s):
    """Hitung jumlah leading zero bytes"""
    count = 0
    for c in s:
        if c == "\0":
            count += 1
        else:
            break
    return count

def base58_check_encode(prefix, payload, compressed=False):
    """Encode ke Base58Check format"""
    s = prefix + payload
    if compressed:
        s = prefix + payload + b"\x01"
    checksum = hashlib.sha256(hashlib.sha256(s).digest()).digest()[0:4]
    result = s + checksum
    return "1" * count_leading_zeroes(result) + b58encode(result).decode()

def pub_key_to_addr(pubkey_hex):
    """Generate Bitcoin address dari public key hex"""
    try:
        ripemd160 = hashlib.new("ripemd160")
        hash_sha256 = hashlib.new("SHA256")
        hash_sha256.update(bytes.fromhex(pubkey_hex))
        ripemd160.update(hash_sha256.digest())
        return base58_check_encode(b"\0", ripemd160.digest())
    except:
        try:
            sha256_hash = hashlib.sha256(bytes.fromhex(pubkey_hex)).digest()
            double_hash = hashlib.sha256(hashlib.sha256(sha256_hash).digest()).digest()
            pseudo_ripemd = double_hash[:20]
            return base58_check_encode(b"\0", pseudo_ripemd)
        except:
            return "1ErrorAddress"

# ========== SIMPLE ELECTRUM UTILITIES ==========
def create_ssl_context():
    """Create SSL context"""
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    return ssl_context

def get_server():
    """Dapatkan satu server dari cache"""
    with server_cache_lock:
        if not healthy_servers:
            return None
        return random.choice(healthy_servers)

def check_balance_simple(address):
    """Check balance dengan cara sederhana dan cepat"""
    if not CHECK_BALANCE:
        return 0
    
    server = get_server()
    if not server:
        return 0
    
    try:
        # Gunakan requests sebagai fallback yang lebih sederhana
        # Electrum API via HTTP (banyak server support ini)
        url = f"http://{server['host']}:{server.get('http_port', 8080) if 'http_port' in server else 8080}/api/address/{address}"
        try:
            import requests
            response = requests.get(url, timeout=2)
            if response.status_code == 200:
                data = response.json()
                return data.get('balance', 0)
        except:
            pass
        
        # Fallback ke blockchain.info
        url = f"https://blockchain.info/balance?active={address}"
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            data = response.json()
            return data.get(address, {}).get('final_balance', 0)
        
        return 0
    except:
        return 0

# ========== BALANCE CHECKER POOL ==========
class BalanceCheckerPool:
    """Pool untuk mengecek balance secara paralel"""
    
    def __init__(self, size=4):
        self.size = size
        self.executor = ThreadPoolExecutor(max_workers=size)
        self.address_queue = []
        self.result_cache = {}
        self.cache_lock = threading.Lock()
        self.cache_expiry = {}
        self.max_cache_age = 300  # 5 menit
        
    def check_balance_batch(self, addresses):
        """Check balance untuk batch addresses"""
        if not addresses:
            return {}
        
        # Filter addresses yang sudah di cache
        current_time = time.time()
        results = {}
        addresses_to_check = []
        
        with self.cache_lock:
            for address in addresses:
                if address in self.result_cache and current_time < self.cache_expiry.get(address, 0):
                    results[address] = self.result_cache[address]
                else:
                    addresses_to_check.append(address)
        
        # Jika semua sudah di cache, return
        if not addresses_to_check:
            return results
        
        # Check balance untuk addresses yang belum di cache
        batch_results = {}
        
        # Submit tasks
        futures = {}
        for address in addresses_to_check:
            future = self.executor.submit(check_balance_simple, address)
            futures[future] = address
        
        # Collect results
        for future in as_completed(futures):
            address = futures[future]
            try:
                balance = future.result(timeout=BALANCE_TIMEOUT)
                batch_results[address] = balance
                
                # Update cache
                with self.cache_lock:
                    self.result_cache[address] = balance
                    self.cache_expiry[address] = current_time + self.max_cache_age
            except:
                batch_results[address] = 0
        
        # Merge results
        results.update(batch_results)
        return results
    
    def shutdown(self):
        """Shutdown pool"""
        self.executor.shutdown(wait=False)

# ========== WALLET GENERATION ==========
def generate_wallet(key_number, balance_checker=None):
    """Generate Bitcoin wallet dari number"""
    try:
        # Convert number to hex key
        hex_key = hex(key_number)[2:].zfill(64)
        if len(hex_key) > 64:
            hex_key = hex_key[-64:]
        
        # 1. Generate Private Key (WIF)
        private_key_wif = base58_check_encode(b"\x80", unhexlify(hex_key), True)
        
        # 2. Generate Public Key dengan k*G
        x, y = str(g * key_number).split()
        x = x.zfill(64)
        y = y.zfill(64)
        
        # Compressed public key
        pk_prefix = "02" if int(y, 16) % 2 == 0 else "03"
        public_key_compressed = pk_prefix + x
        
        # 3. Generate Bitcoin Address
        address = pub_key_to_addr(public_key_compressed)
        
        # 4. Cek Balance jika diaktifkan
        balance = 0
        if CHECK_BALANCE and balance_checker:
            # Gunakan balance checker pool
            results = balance_checker.check_balance_batch([address])
            balance = results.get(address, 0)
        
        return {
            'number': key_number,
            'private_key': private_key_wif,
            'public_key': public_key_compressed,
            'address': address,
            'balance': balance,
            'timestamp': datetime.now().isoformat()
        }
        
    except Exception as e:
        return None

def process_batch(batch_numbers, balance_checker=None):
    """Process batch of numbers dengan multithreading"""
    results = []
    
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        # Submit semua tasks
        futures = {}
        for num in batch_numbers:
            future = executor.submit(generate_wallet, num, balance_checker)
            futures[future] = num
        
        # Collect results
        completed = 0
        for future in as_completed(futures):
            completed += 1
            try:
                result = future.result(timeout=10)
                if result:
                    results.append(result)
            except:
                continue
    
    return results

def save_wallet_result(result):
    """Save wallet result ke file"""
    try:
        with file_lock:
            # Selalu simpan ke wallets.txt
            with open(WALLETS_FILE, "a", encoding="utf-8") as f:
                f.write(f"{'='*60}\n")
                f.write(f"Number: {result['number']}\n")
                f.write(f"Private Key (WIF): {result['private_key']}\n")
                f.write(f"Public Key: {result['public_key']}\n")
                f.write(f"Address: {result['address']}\n")
                f.write(f"Balance: {result['balance']} satoshi\n")
                f.write(f"Time: {result['timestamp']}\n")
                f.write(f"{'='*60}\n\n")
            
            # Jika ada balance > 0, simpan ke rich_wallets.txt
            if result['balance'] > 0:
                with open(RICH_WALLETS_FILE, "a", encoding="utf-8") as f:
                    f.write(f"{'#'*80}\n")
                    f.write(f"🎯 WALLET DENGAN SALDO DITEMUKAN! 🎯\n")
                    f.write(f"{'#'*80}\n")
                    f.write(f"Number: {result['number']}\n")
                    f.write(f"Private Key: {result['private_key']}\n")
                    f.write(f"Address: {result['address']}\n")
                    f.write(f"Balance: {result['balance']} satoshi\n")
                    
                    # Konversi ke BTC
                    btc_balance = result['balance'] / 100000000
                    f.write(f"Balance: {btc_balance:.8f} BTC\n")
                    
                    f.write(f"Time: {result['timestamp']}\n")
                    f.write(f"{'#'*80}\n\n")
                
                return True
        
        return False
        
    except Exception as e:
        return False

# ========== DISPLAY PROGRESS ==========
def display_progress(stats, start_time, batch_num, last_update):
    """Display progress bar dan statistik"""
    current_time = time.time()
    elapsed = current_time - start_time
    processed = stats.get('processed', 0)
    rich_found = stats.get('rich_found', 0)
    
    if processed > 0 and elapsed > 0:
        keys_per_sec = processed / elapsed
        time_per_wallet = elapsed / processed * 1000  # ms per wallet
    else:
        keys_per_sec = 0
        time_per_wallet = 0
    
    # Progress bar
    bar_length = 40
    progress_percent = min(100, (processed % 500) * 100 / 500)
    
    filled = int(bar_length * progress_percent / 100)
    bar = '█' * filled + '░' * (bar_length - filled)
    
    # Format waktu
    hours = int(elapsed // 3600)
    minutes = int((elapsed % 3600) // 60)
    seconds = int(elapsed % 60)
    time_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    
    # Status servers
    with server_cache_lock:
        server_status = f"{len(healthy_servers)}/{len(ELECTRUM_SERVERS)}"
    
    # Tampilkan
    progress_line = (
        f"\r[{bar}] {progress_percent:5.1f}% | "
        f"Batch: {batch_num:3d} | "
        f"Wallets: {processed:6,} | "
        f"Rich: {rich_found:3d} | "
        f"Speed: {keys_per_sec:5.1f}/s | "
        f"Servers: {server_status} | "
        f"Time: {time_str}"
    )
    
    with print_lock:
        sys.stdout.write(progress_line)
        sys.stdout.flush()
    
    return current_time

def print_banner():
    """Tampilkan banner program"""
    os.system('cls' if os.name == 'nt' else 'clear')
    
    banner = f"""
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║  ██████  ██████  ████████ ██████  ██████  ██ ███    ██ ██████   ║
║  ██   ██ ██   ██    ██    ██   ██ ██   ██ ██ ████   ██ ██   ██  ║
║  ██████  ██████     ██    ██████  ██████  ██ ██ ██  ██ ██   ██  ║
║  ██   ██ ██   ██    ██    ██      ██   ██ ██ ██  ██ ██ ██   ██  ║
║  ██████  ██   ██    ██    ██      ██   ██ ██ ██   ████ ██████   ║
║                                                                  ║
║               BITCOIN WALLET SCANNER v3.2                        ║
║           OPTIMIZED Balance Checker Pool                         ║
║               Author: MMDRZA.COM                                 ║
║                                                                  ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  [✓] Mode: Random Scanning (Optimized)                           ║
║  [✓] Generation Threads: {MAX_THREADS:<2}                          ║
║  [✓] Balance Checker Pool: {BALANCE_POOL_SIZE:<2} threads          ║
║  [✓] Balance Checking: {("ENABLED" if CHECK_BALANCE else "DISABLED"):<8} ║
║  [✓] Batch Size: {BATCH_SIZE:<4}                                ║
║  [✓] Timeout: {BALANCE_TIMEOUT}s per balance check              ║
║                                                                  ║
║  Press Ctrl+C to stop                                           ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
"""
    
    print(banner)
    print("\n" + "=" * 70)
    print("Starting optimized wallet generation with balance checker pool...")
    print("=" * 70)

# ========== HEALTH CHECK ==========
def simple_health_check():
    """Health check sederhana menggunakan requests"""
    global healthy_servers, last_health_check
    
    current_time = time.time()
    if current_time - last_health_check < HEALTH_CHECK_INTERVAL:
        return
    
    log_message("Performing health check...", "INFO")
    
    new_healthy_servers = []
    
    for server in ELECTRUM_SERVERS:
        try:
            # Coba koneksi sederhana
            import requests
            # Coba port 80/443 untuk HTTP API
            test_urls = [
                f"http://{server['host']}:80/",
                f"http://{server['host']}:8080/",
                f"https://{server['host']}:443/"
            ]
            
            success = False
            for url in test_urls:
                try:
                    response = requests.get(url, timeout=2)
                    if response.status_code < 500:  # Tidak error server
                        success = True
                        break
                except:
                    continue
            
            if success:
                new_healthy_servers.append(server)
                log_message(f"✅ Server {server['host']} is reachable", "INFO")
            else:
                log_message(f"❌ Server {server['host']} not reachable", "WARNING")
                
        except Exception as e:
            continue
    
    with server_cache_lock:
        healthy_servers = new_healthy_servers
        last_health_check = current_time
    
    if not healthy_servers:
        log_message("⚠️ No servers available, using fallback method", "WARNING")
    else:
        log_message(f"✅ Health check complete: {len(healthy_servers)} servers available", "INFO")

# ========== INITIALIZE ==========
def initialize():
    """Initialize program"""
    global balance_pool
    
    log_message("Initializing...", "INFO")
    
    # Simple health check
    simple_health_check()
    
    # Setup balance checker pool
    if CHECK_BALANCE and USE_BALANCE_POOL:
        balance_pool = BalanceCheckerPool(size=BALANCE_POOL_SIZE)
        log_message(f"Balance checker pool initialized with {BALANCE_POOL_SIZE} threads", "INFO")
    
    log_message("Initialization complete", "INFO")
    return balance_pool

# ========== MAIN SCANNER ==========
def main_scanner():
    """Main scanner function"""
    # Tampilkan banner
    print_banner()
    
    # Initialize
    balance_checker = initialize()
    
    # Load progress
    wallets_generated = load_progress()
    log_message(f"Resuming from {wallets_generated:,} wallets generated", "INFO")
    
    # Stats
    stats = {
        'processed': wallets_generated,
        'rich_found': 0,
        'start_time': time.time(),
        'last_save': wallets_generated,
        'last_health_check': time.time()
    }
    
    try:
        batch_counter = 0
        last_progress_update = time.time()
        
        while True:
            batch_counter += 1
            
            # Periodic health check setiap 5 menit
            current_time = time.time()
            if current_time - stats['last_health_check'] > 300:  # 5 menit
                simple_health_check()
                stats['last_health_check'] = current_time
            
            # Generate batch
            batch_numbers = [random.randint(1, 10**30) for _ in range(BATCH_SIZE)]
            
            # Process batch
            batch_start = time.time()
            batch_results = process_batch(batch_numbers, balance_checker)
            batch_time = time.time() - batch_start
            
            # Process results
            batch_rich = 0
            for result in batch_results:
                stats['processed'] += 1
                
                if save_wallet_result(result):
                    batch_rich += 1
                    stats['rich_found'] += 1
                    
                    # Alert untuk wallet dengan saldo
                    with print_lock:
                        print(f"\n\n{'!'*80}")
                        print(f"🎯 WALLET DENGAN SALDO DITEMUKAN! 🎯")
                        print(f"Address: {result['address']}")
                        print(f"Balance: {result['balance']} satoshi")
                        print(f"{'!'*80}\n")
            
            # Display progress
            last_progress_update = display_progress(stats, stats['start_time'], batch_counter, last_progress_update)
            
            # Log batch info setiap 3 batch atau jika batch lama
            if batch_counter % 3 == 0 or batch_time > 20:
                elapsed = time.time() - stats['start_time']
                keys_per_sec = stats['processed'] / elapsed if elapsed > 0 else 0
                
                with server_cache_lock:
                    server_count = len(healthy_servers)
                
                log_message(
                    f"Batch {batch_counter}: {len(batch_results)} wallets, "
                    f"{batch_rich} rich, time: {batch_time:.1f}s, "
                    f"speed: {keys_per_sec:.1f}/s, servers: {server_count}",
                    "INFO"
                )
            
            # Save progress
            if stats['processed'] - stats['last_save'] >= SAVE_INTERVAL:
                save_progress(stats['processed'], stats['start_time'])
                stats['last_save'] = stats['processed']
            
            # Small delay untuk kontrol CPU
            time.sleep(0.05)
            
    except KeyboardInterrupt:
        print("\n\n" + "=" * 70)
        log_message("Scan interrupted by user", "INFO")
        return stats
    except Exception as e:
        log_message(f"Scanner error: {e}", "ERROR")
        import traceback
        traceback.print_exc()
        return stats

# ========== MAIN FUNCTION ==========
def main():
    """Entry point utama"""
    try:
        final_stats = main_scanner()
        
    except KeyboardInterrupt:
        print("\n" + "=" * 70)
        print("SCAN INTERRUPTED")
        print("=" * 70)
        final_stats = {'processed': 0, 'rich_found': 0, 'start_time': time.time()}
    except Exception as e:
        log_message(f"Fatal error: {e}", "CRITICAL")
        final_stats = {'processed': 0, 'rich_found': 0, 'start_time': time.time()}
    
    finally:
        # Cleanup
        if balance_pool:
            balance_pool.shutdown()
        
        # Final stats
        print("\n" + "=" * 70)
        print("FINAL STATISTICS")
        print("=" * 70)
        
        elapsed = time.time() - final_stats.get('start_time', time.time())
        processed = final_stats.get('processed', 0)
        rich_found = final_stats.get('rich_found', 0)
        
        print(f"Total wallets generated: {processed:,}")
        print(f"Wallets with balance found: {rich_found:,}")
        print(f"Total time: {elapsed:.2f} seconds")
        
        if processed > 0:
            keys_per_sec = processed / elapsed
            print(f"Average speed: {keys_per_sec:.2f} wallets/second")
        
        print(f"\nResults saved in:")
        print(f"  - {WALLETS_FILE} (all wallets)")
        if rich_found > 0:
            print(f"  - {RICH_WALLETS_FILE} (wallets with balance)")
        print(f"  - {LOG_FILE} (activity log)")
        print("=" * 70)
        
        save_progress(processed, final_stats.get('start_time', time.time()))
        input("\nPress Enter to exit...")

# ========== START PROGRAM ==========
if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    main()
