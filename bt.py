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
import concurrent.futures

from utils import g, b58encode

# ========== KONFIGURASI ==========
MAX_THREADS = 8                     # Thread untuk wallet generation
BATCH_SIZE = 1000                   # Ukuran batch
CHECK_BALANCE = True               # Aktifkan pengecekan balance
SAVE_INTERVAL = 1000               # Simpan progress setiap 1000 wallet
MAX_RETRIES = 1                    # Retry untuk koneksi
CONNECTION_TIMEOUT = 5             # Timeout koneksi
USE_SIMPLE_BALANCE = True          # Gunakan metode simple untuk balance check

# ========== INISIALISASI ==========
PACKER = Struct(">QQQQ")
file_lock = threading.Lock()
print_lock = threading.Lock()

# File output
WALLETS_FILE = "wallets.txt"
RICH_WALLETS_FILE = "rich_wallets.txt"
LOG_FILE = "scan.log"
PROGRESS_FILE = "progress.txt"

# ========== ELECTRUM SERVER LIST ==========
ELECTRUM_SERVERS = [
    {"host": "bitcoin.aranguren.org", "port": 50002},
    {"host": "electrum.loyce.club", "port": 50002},
    {"host": "electrum.emzy.de", "port": 50002},
    {"host": "electrum.blockstream.info", "port": 50002},
]

# ========== GLOBAL EVENT LOOP ==========
# Buat event loop di main thread
main_event_loop = None
server_cache = []
cache_lock = threading.Lock()
cache_expiry = 0
CACHE_DURATION = 300  # 5 menit

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
        # Method 1: Coba hashlib dengan RIPEMD-160
        ripemd160 = hashlib.new("ripemd160")
        hash_sha256 = hashlib.new("SHA256")
        hash_sha256.update(bytes.fromhex(pubkey_hex))
        ripemd160.update(hash_sha256.digest())
        return base58_check_encode(b"\0", ripemd160.digest())
    except:
        try:
            # Method 2: Fallback
            sha256_hash = hashlib.sha256(bytes.fromhex(pubkey_hex)).digest()
            double_hash = hashlib.sha256(hashlib.sha256(sha256_hash).digest()).digest()
            pseudo_ripemd = double_hash[:20]
            return base58_check_encode(b"\0", pseudo_ripemd)
        except Exception as e:
            return "1ErrorAddress"

# ========== ELECTRUM UTILITIES (FIXED) ==========
def address_to_scripthash_simple(address: str) -> str:
    """Convert Bitcoin address to script hash (simplified)"""
    try:
        if address.startswith("1"):  # P2PKH
            decoded = base58.b58decode_check(address)
            payload = decoded[1:]
            script = b"\x76\xa9\x14" + payload + b"\x88\xac"
        elif address.startswith("3"):  # P2SH
            decoded = base58.b58decode_check(address)
            payload = decoded[1:]
            script = b"\xa9\x14" + payload + b"\x87"
        elif address.startswith("bc1"):  # Bech32
            # Simple fallback untuk bech32
            hrp = "bc"
            witver, witprog = bech32.decode(hrp, address)
            if witver == 0:
                if len(witprog) == 20:
                    script = bytes([0x00, 0x14]) + bytes(witprog)
                else:
                    script = bytes([0x00, 0x20]) + bytes(witprog)
            else:
                script = bytes([0x51, 0x20]) + bytes(witprog)
        else:
            return "00" * 32
        
        scripthash = hashlib.sha256(script).digest()[::-1].hex()
        return scripthash
    except Exception as e:
        return "00" * 32

def create_ssl_context():
    """Create SSL context"""
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    return ssl_context

async def check_server_health_async(server_info):
    """Check server health asynchronously"""
    try:
        ssl_context = create_ssl_context()
        async with connect_rs(
            server_info["host"], 
            server_info["port"], 
            ssl=ssl_context
        ) as session:
            result = await asyncio.wait_for(
                session.send_request("server.ping", []),
                timeout=3
            )
            return True
    except:
        return False

async def get_healthy_servers_async():
    """Get healthy servers asynchronously"""
    tasks = []
    for server in ELECTRUM_SERVERS:
        tasks.append(check_server_health_async(server))
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    healthy = []
    for i, result in enumerate(results):
        if result is True:
            healthy.append(ELECTRUM_SERVERS[i])
    
    return healthy

def get_healthy_servers_sync():
    """Get healthy servers synchronously (run in main event loop)"""
    global main_event_loop, server_cache, cache_expiry
    
    current_time = time.time()
    
    # Cek cache
    with cache_lock:
        if server_cache and current_time < cache_expiry:
            return server_cache.copy()
    
    # Jika cache expired atau kosong, fetch baru
    if main_event_loop is None:
        return []  # Event loop belum diinisialisasi
    
    try:
        # Jalankan di main event loop
        healthy_servers = asyncio.run_coroutine_threadsafe(
            get_healthy_servers_async(),
            main_event_loop
        ).result(timeout=10)
        
        with cache_lock:
            server_cache = healthy_servers.copy()
            cache_expiry = current_time + CACHE_DURATION
        
        log_message(f"Found {len(healthy_servers)} healthy servers", "INFO")
        return healthy_servers
    except Exception as e:
        log_message(f"Error getting healthy servers: {e}", "ERROR")
        return []

async def check_balance_single_async(address, server_info):
    """Check balance for single address asynchronously"""
    try:
        ssl_context = create_ssl_context()
        async with connect_rs(
            server_info["host"], 
            server_info["port"], 
            ssl=ssl_context
        ) as session:
            scripthash = address_to_scripthash_simple(address)
            result = await asyncio.wait_for(
                session.send_request("blockchain.scripthash.get_balance", [scripthash]),
                timeout=CONNECTION_TIMEOUT
            )
            
            if isinstance(result, dict):
                return result.get("confirmed", 0) + result.get("unconfirmed", 0)
            return 0
    except:
        return 0

def check_balance_single_sync(address):
    """Check balance synchronously using thread pool"""
    if not CHECK_BALANCE:
        return 0
    
    healthy_servers = get_healthy_servers_sync()
    if not healthy_servers:
        return 0
    
    # Pilih server random
    server = random.choice(healthy_servers)
    
    # Jalankan async function di thread pool
    try:
        if main_event_loop is None:
            return 0
        
        # Submit task ke event loop
        future = asyncio.run_coroutine_threadsafe(
            check_balance_single_async(address, server),
            main_event_loop
        )
        
        # Tunggu hasil dengan timeout
        balance = future.result(timeout=CONNECTION_TIMEOUT + 2)
        return balance
    except:
        return 0

# ========== WALLET GENERATION ==========
def generate_wallet(key_number):
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
        if CHECK_BALANCE and USE_SIMPLE_BALANCE:
            balance = check_balance_single_sync(address)
        
        result = {
            'number': key_number,
            'private_key': private_key_wif,
            'public_key': public_key_compressed,
            'address': address,
            'balance': balance,
            'timestamp': datetime.now().isoformat()
        }
        
        return result
        
    except Exception as e:
        return None

def process_batch(batch_numbers):
    """Process batch of numbers dengan multithreading"""
    results = []
    
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(generate_wallet, num): num for num in batch_numbers}
        
        for future in as_completed(futures):
            try:
                result = future.result(timeout=10)
                if result:
                    results.append(result)
            except Exception as e:
                continue  # Skip error, continue
    
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
def display_progress(stats, start_time, batch_num):
    """Display progress bar dan statistik"""
    elapsed = time.time() - start_time
    processed = stats.get('processed', 0)
    rich_found = stats.get('rich_found', 0)
    
    if processed > 0 and elapsed > 0:
        keys_per_sec = processed / elapsed
    else:
        keys_per_sec = 0
    
    # Progress bar
    bar_length = 40
    progress_percent = min(100, (processed % 1000) * 100 / 1000)
    
    filled = int(bar_length * progress_percent / 100)
    bar = '█' * filled + '░' * (bar_length - filled)
    
    # Format waktu
    hours = int(elapsed // 3600)
    minutes = int((elapsed % 3600) // 60)
    seconds = int(elapsed % 60)
    time_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    
    # Tampilkan
    progress_line = (
        f"\r[{bar}] {progress_percent:5.1f}% | "
        f"Batch: {batch_num:3d} | "
        f"Wallets: {processed:9,} | "
        f"Rich: {rich_found:3,} | "
        f"Speed: {keys_per_sec:6.1f}/s | "
        f"Time: {time_str}"
    )
    
    with print_lock:
        sys.stdout.write(progress_line)
        sys.stdout.flush()

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
║               BITCOIN WALLET SCANNER v3.1                        ║
║           FIXED Event Loop Management                            ║
║               Author: MMDRZA.COM                                 ║
║                                                                  ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  [✓] Mode: Random Scanning                                       ║
║  [✓] Threads: {MAX_THREADS:<3}                                     ║
║  [✓] Balance Checking: {("ENABLED" if CHECK_BALANCE else "DISABLED"):<10}         ║
║  [✓] Electrum Servers: {len(ELECTRUM_SERVERS):<3}                               ║
║  [✓] Batch Size: {BATCH_SIZE:<6}                                  ║
║  [✓] Timeout: {CONNECTION_TIMEOUT}s                               ║
║                                                                  ║
║  Press Ctrl+C to stop                                           ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
"""
    
    print(banner)
    print("\n" + "=" * 70)
    print("Starting random wallet generation with FIXED event loop...")
    print("=" * 70)

# ========== INITIALIZE ==========
def initialize():
    """Initialize program"""
    global main_event_loop
    
    log_message("Initializing...", "INFO")
    
    # Setup event loop dengan cara yang benar
    try:
        # Coba dapatkan running loop
        main_event_loop = asyncio.get_running_loop()
    except RuntimeError:
        # Jika tidak ada, buat baru
        main_event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(main_event_loop)
    
    # Start event loop thread
    def run_event_loop():
        asyncio.set_event_loop(main_event_loop)
        main_event_loop.run_forever()
    
    event_loop_thread = threading.Thread(target=run_event_loop, daemon=True)
    event_loop_thread.start()
    
    # Tunggu event loop ready
    time.sleep(1)
    
    # Health check servers
    if CHECK_BALANCE:
        healthy_servers = get_healthy_servers_sync()
        if not healthy_servers:
            log_message("WARNING: No healthy Electrum servers found", "WARNING")
        else:
            log_message(f"✅ {len(healthy_servers)} Electrum servers ready", "INFO")
    
    log_message("Initialization complete", "INFO")

# ========== MAIN SCANNER ==========
def main_scanner():
    """Main scanner function"""
    # Tampilkan banner
    print_banner()
    
    # Initialize
    initialize()
    
    # Load progress
    wallets_generated = load_progress()
    log_message(f"Resuming from {wallets_generated:,} wallets generated", "INFO")
    
    # Stats
    stats = {
        'processed': wallets_generated,
        'rich_found': 0,
        'start_time': time.time(),
        'last_save': wallets_generated
    }
    
    try:
        batch_counter = 0
        
        while True:
            batch_counter += 1
            
            # Generate batch
            batch_numbers = [random.randint(1, 10**30) for _ in range(BATCH_SIZE)]
            
            # Process batch
            batch_start = time.time()
            batch_results = process_batch(batch_numbers)
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
            display_progress(stats, stats['start_time'], batch_counter)
            
            # Log batch info
            if batch_counter % 5 == 0 or batch_time > 30:
                elapsed = time.time() - stats['start_time']
                keys_per_sec = stats['processed'] / elapsed if elapsed > 0 else 0
                
                log_message(
                    f"Batch {batch_counter}: {len(batch_results)} wallets, "
                    f"{batch_rich} rich, time: {batch_time:.1f}s, "
                    f"total: {stats['processed']:,}, speed: {keys_per_sec:.1f}/s",
                    "INFO"
                )
            
            # Save progress
            if stats['processed'] - stats['last_save'] >= SAVE_INTERVAL:
                save_progress(stats['processed'], stats['start_time'])
                stats['last_save'] = stats['processed']
            
            # Small delay
            time.sleep(0.1)
            
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
        # Stop event loop
        if main_event_loop and main_event_loop.is_running():
            main_event_loop.call_soon_threadsafe(main_event_loop.stop)
        
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
