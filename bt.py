import os
import sys
import time
import random
import threading
import hashlib
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
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
MAX_THREADS = 8                     # KURANGI dari 12 ke 8 (lebih stabil)
BATCH_SIZE = 1000                   # KURANGI dari 5000 ke 1000 (batch lebih kecil)
CHECK_BALANCE = True               # Aktifkan pengecekan balance
SAVE_INTERVAL = 1000               # Simpan progress setiap 1000 wallet
MAX_RETRIES = 1                    # KURANGI retry (1 saja, lebih cepat)
CONNECTION_TIMEOUT = 5             # KURANGI timeout dari 8 ke 5 detik
WALLET_TIMEOUT = 8                 # Timeout untuk generate_wallet (detik)
DISABLE_ELECTRUM_IF_SLOW = True    # Nonaktifkan Electrum jika terlalu lambat
ELECTRUM_SLOW_THRESHOLD = 10       # Jika >10 detik per wallet, disable

# ========== INISIALISASI ==========
PACKER = Struct(">QQQQ")            # Untuk konversi 256-bit integer
file_lock = threading.Lock()        # Lock untuk thread-safe file operations
print_lock = threading.Lock()       # Lock untuk thread-safe printing

# File output
WALLETS_FILE = "wallets.txt"        # Semua wallet yang digenerate
RICH_WALLETS_FILE = "rich_wallets.txt"  # Wallet dengan balance
LOG_FILE = "scan.log"               # File log aktivitas
PROGRESS_FILE = "progress.txt"      # Progress checkpoint

# ========== ELECTRUM SERVER LIST (SIMPLE) ==========
ELECTRUM_SERVERS = [
    {"host": "bitcoin.aranguren.org", "port": 50002},
    {"host": "electrum.loyce.club", "port": 50002},
    {"host": "electrum.emzy.de", "port": 50002},  # Server alternatif
    {"host": "electrum.blockstream.info", "port": 50002},  # Server alternatif
]

# ========== SHARED GLOBAL STATE ==========
healthy_servers = []
healthy_servers_lock = threading.Lock()
last_health_check = 0
HEALTH_CHECK_INTERVAL = 1800  # 30 menit
electrum_disabled = False  # Flag untuk nonaktifkan Electrum jika lambat
start_time = time.time()
wallets_processed = 0

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
            # Method 2: Fallback ke implementasi alternatif
            # SHA256 hash
            sha256_hash = hashlib.sha256(bytes.fromhex(pubkey_hex)).digest()
            # Double SHA256 dan ambil 20 byte pertama sebagai pengganti RIPEMD160
            double_hash = hashlib.sha256(hashlib.sha256(sha256_hash).digest()).digest()
            pseudo_ripemd = double_hash[:20]
            return base58_check_encode(b"\0", pseudo_ripemd)
        except Exception as e:
            return "1ErrorAddress"  # Return address error tanpa log

# ========== ELECTRUM UTILITIES (SIMPLIFIED) ==========
def address_to_scripthash(address: str) -> str:
    """Convert Bitcoin address to script hash for Electrum API"""
    try:
        if address.startswith("1"):  # P2PKH
            decoded = base58.b58decode_check(address)
            payload = decoded[1:]
            script = b"\x76\xa9\x14" + payload + b"\x88\xac"
        elif address.startswith("3"):  # P2SH
            decoded = base58.b58decode_check(address)
            payload = decoded[1:]
            script = b"\xa9\x14" + payload + b"\x87"
        else:
            # Untuk simplicity, skip segwit jika complex
            raise ValueError("Unsupported address type")
        
        scripthash = hashlib.sha256(script).digest()[::-1].hex()
        return scripthash
    except:
        return "00" * 32  # Return dummy scripthash

def create_ssl_context():
    """Create SSL context untuk koneksi Electrum"""
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    return ssl_context

async def check_server_health_quick(server_info):
    """Cek kesehatan server dengan cepat"""
    try:
        ssl_context = create_ssl_context()
        async with connect_rs(
            server_info["host"], 
            server_info["port"], 
            ssl=ssl_context
        ) as session:
            # Quick ping
            await asyncio.wait_for(
                session.send_request("server.ping", []),
                timeout=3
            )
            return True
    except:
        return False

async def quick_health_check():
    """Health check cepat"""
    global healthy_servers, last_health_check, electrum_disabled
    
    tasks = []
    for server in ELECTRUM_SERVERS:
        task = asyncio.create_task(check_server_health_quick(server))
        tasks.append((server, task))
    
    new_healthy_servers = []
    for server, task in tasks:
        try:
            is_healthy = await asyncio.wait_for(task, timeout=5)
            if is_healthy:
                new_healthy_servers.append(server)
        except:
            continue
    
    with healthy_servers_lock:
        healthy_servers = new_healthy_servers
        last_health_check = time.time()
    
    if not healthy_servers:
        electrum_disabled = True
        log_message("⚠️ Semua server Electrum mati, menonaktifkan balance check", "WARNING")
    else:
        log_message(f"✅ {len(healthy_servers)} server Electrum siap", "INFO")

def get_healthy_server_fast():
    """Dapatkan server sehat dengan cepat"""
    global electrum_disabled
    
    if electrum_disabled:
        return None
    
    with healthy_servers_lock:
        if not healthy_servers:
            return None
        return random.choice(healthy_servers)

async def check_balance_fast(address, server_info):
    """Check balance dengan cepat"""
    if not server_info:
        return 0
    
    try:
        ssl_context = create_ssl_context()
        async with connect_rs(
            server_info["host"], 
            server_info["port"], 
            ssl=ssl_context
        ) as session:
            scripthash = address_to_scripthash(address)
            result = await asyncio.wait_for(
                session.send_request("blockchain.scripthash.get_balance", [scripthash]),
                timeout=CONNECTION_TIMEOUT
            )
            
            if isinstance(result, dict):
                return result.get("confirmed", 0) + result.get("unconfirmed", 0)
            return 0
    except:
        return 0

def check_balance_quick(address):
    """Cek balance dengan cepat (synchronous)"""
    global electrum_disabled
    
    if electrum_disabled or not CHECK_BALANCE:
        return 0
    
    server = get_healthy_server_fast()
    if not server:
        return 0
    
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        balance = loop.run_until_complete(check_balance_fast(address, server))
        loop.close()
        return balance
    except:
        return 0

# ========== WALLET GENERATION (OPTIMIZED) ==========
def generate_wallet_fast(key_number):
    """Generate wallet dengan cepat"""
    try:
        # Convert number to hex key
        hex_key = hex(key_number)[2:].zfill(64)
        if len(hex_key) > 64:
            hex_key = hex_key[-64:]
        
        # 1. Private Key
        private_key_wif = base58_check_encode(b"\x80", unhexlify(hex_key), True)
        
        # 2. Public Key
        x, y = str(g * key_number).split()
        x = x.zfill(64)
        y = y.zfill(64)
        
        # Compressed public key
        pk_prefix = "02" if int(y, 16) % 2 == 0 else "03"
        public_key_compressed = pk_prefix + x
        
        # 3. Address
        address = pub_key_to_addr(public_key_compressed)
        
        # 4. Balance check (OPTIONAL - bisa skip jika lambat)
        balance = 0
        if CHECK_BALANCE and not electrum_disabled:
            # Coba cek balance, tapi timeout cepat
            try:
                balance = check_balance_quick(address)
            except:
                balance = 0
        
        return {
            'number': key_number,
            'private_key': private_key_wif,
            'public_key': public_key_compressed,
            'address': address,
            'balance': balance,
            'timestamp': datetime.now().isoformat()
        }
        
    except Exception as e:
        return None  # Skip error, continue

def process_batch_fast(batch_numbers):
    """Process batch dengan timeout management"""
    global electrum_disabled
    
    results = []
    batch_start = time.time()
    
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(generate_wallet_fast, num): num for num in batch_numbers}
        
        for future in as_completed(futures):
            try:
                result = future.result(timeout=WALLET_TIMEOUT)
                if result:
                    results.append(result)
            except TimeoutError:
                # Thread timeout, skip wallet ini
                continue
            except Exception:
                # Error lain, continue
                continue
    
    batch_end = time.time()
    batch_time = batch_end - batch_start
    avg_time_per_wallet = batch_time / len(batch_numbers) if batch_numbers else 0
    
    # Jika terlalu lambat, disable Electrum
    if (DISABLE_ELECTRUM_IF_SLOW and CHECK_BALANCE and not electrum_disabled and 
        avg_time_per_wallet > ELECTRUM_SLOW_THRESHOLD):
        electrum_disabled = True
        log_message(f"⚠️ Electrum terlalu lambat ({avg_time_per_wallet:.1f}s/wallet), menonaktifkan balance check", "WARNING")
    
    return results

# ========== PROGRESS DISPLAY ==========
def display_progress_enhanced(stats, start_time, batch_num, active_threads=0):
    """Display progress dengan info lebih detail"""
    elapsed = time.time() - start_time
    processed = stats.get('processed', 0)
    rich_found = stats.get('rich_found', 0)
    
    if processed > 0 and elapsed > 0:
        keys_per_sec = processed / elapsed
        estimated_total = elapsed / processed if processed > 0 else 0
    else:
        keys_per_sec = 0
        estimated_total = 0
    
    # Progress bar
    bar_length = 40
    filled = int(bar_length * (processed % 1000) / 1000)
    bar = '█' * filled + '░' * (bar_length - filled)
    
    # Format waktu
    hours = int(elapsed // 3600)
    minutes = int((elapsed % 3600) // 60)
    seconds = int(elapsed % 60)
    time_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    
    # Status Electrum
    electrum_status = "✅" if CHECK_BALANCE and not electrum_disabled else "❌"
    
    # Tampilkan
    progress_line = (
        f"\r[{bar}] | "
        f"Batch: {batch_num:3d} | "
        f"Wallets: {processed:6,} | "
        f"Rich: {rich_found:3d} | "
        f"Speed: {keys_per_sec:5.1f}/s | "
        f"Electrum: {electrum_status} | "
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
║               BITCOIN WALLET SCANNER v2.6                        ║
║               FAST MODE - No Stuck Threads                       ║
║               Author: MMDRZA.COM                                 ║
║                                                                  ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  [✓] Mode: Random Scanning (FAST)                                ║
║  [✓] Threads: {MAX_THREADS:<2} (optimized)                                     ║
║  [✓] Batch Size: {BATCH_SIZE:<4} (smaller batches)                          ║
║  [✓] Balance Check: {("ENABLED" if CHECK_BALANCE else "DISABLED"):<8}                     ║
║  [✓] Timeout: {WALLET_TIMEOUT}s per wallet                               ║
║  [✓] Auto-disable Electrum if slow                              ║
║                                                                  ║
║  Press Ctrl+C to stop                                           ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
"""
    
    print(banner)
    print("\n" + "=" * 70)
    print("🚀 FAST MODE: Generating wallets with timeout protection...")
    print("=" * 70)

# ========== INITIALIZE ==========
def initialize_fast():
    """Initialize cepat"""
    global CHECK_BALANCE, electrum_disabled
    
    if CHECK_BALANCE:
        try:
            log_message("Quick Electrum initialization...", "INFO")
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(quick_health_check())
            loop.close()
            
            if electrum_disabled:
                log_message("⚠️ Running WITHOUT balance checking", "WARNING")
            else:
                log_message("✅ Electrum ready", "INFO")
        except:
            electrum_disabled = True
            log_message("⚠️ Electrum init failed, running without balance check", "WARNING")
    else:
        log_message("✅ Running without balance checking", "INFO")

# ========== MAIN SCANNER ==========
def main_scanner_fast():
    """Main scanner fast mode"""
    global wallets_processed, start_time
    
    # Tampilkan banner
    print_banner()
    
    # Initialize cepat
    initialize_fast()
    
    # Load progress
    wallets_generated = load_progress()
    log_message(f"Resuming from {wallets_generated:,} wallets", "INFO")
    
    # Stats
    stats = {
        'processed': wallets_generated,
        'rich_found': 0,
        'start_time': time.time(),
        'last_save': wallets_generated
    }
    
    start_time = time.time()
    
    try:
        batch_counter = 0
        
        while True:
            batch_counter += 1
            
            # Generate batch kecil
            batch_numbers = [random.randint(1, 10**30) for _ in range(BATCH_SIZE)]
            
            # Log batch start
            log_message(f"Batch {batch_counter} started with {BATCH_SIZE} wallets", "INFO")
            
            # Process batch
            batch_start = time.time()
            batch_results = process_batch_fast(batch_numbers)
            batch_end = time.time()
            
            # Process results
            batch_rich = 0
            for result in batch_results:
                stats['processed'] += 1
                wallets_processed += 1
                
                # Save wallet
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
            
            # Tampilkan progress
            display_progress_enhanced(stats, start_time, batch_counter)
            
            # Log batch completion
            batch_time = batch_end - batch_start
            log_message(f"Batch {batch_counter} completed: {len(batch_results)} wallets, {batch_rich} rich, time: {batch_time:.1f}s", "INFO")
            
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
        return stats

# ========== MAIN ==========
def main():
    """Entry point"""
    try:
        final_stats = main_scanner_fast()
    except KeyboardInterrupt:
        print("\n" + "=" * 70)
        print("SCAN INTERRUPTED")
        print("=" * 70)
        final_stats = {'processed': 0, 'rich_found': 0, 'start_time': time.time()}
    except Exception as e:
        log_message(f"Fatal error: {e}", "CRITICAL")
        final_stats = {'processed': 0, 'rich_found': 0, 'start_time': time.time()}
    
    finally:
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
        
        # Simpan progress
        save_progress(processed, final_stats.get('start_time', time.time()))
        
        print("\nResults saved in:")
        print(f"  - {WALLETS_FILE} (all wallets)")
        if rich_found > 0:
            print(f"  - {RICH_WALLETS_FILE} (wallets with balance)")
        print(f"  - {LOG_FILE} (activity log)")
        print("=" * 70)
        
        input("\nPress Enter to exit...")

# ========== START ==========
if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    main()
