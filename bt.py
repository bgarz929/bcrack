import hashlib
import os
import sys
import time
import random
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from binascii import hexlify, unhexlify
from struct import Struct

# Import dari utils
from utils import g, b58encode, b58decode

# ========== KONFIGURASI ==========
MAX_THREADS = 16                    # Jumlah thread maksimal
BATCH_SIZE = 10000                  # Ukuran batch untuk processing
SAVE_INTERVAL = 5000                # Interval penyimpanan progress
MAX_KEY_VALUE = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# ========== INISIALISASI ==========
PACKER = Struct(">QQQQ")            # Untuk konversi 256-bit integer
file_lock = threading.Lock()        # Lock untuk thread-safe file operations
print_lock = threading.Lock()       # Lock untuk thread-safe printing

# File output
RESULTS_FILE = "found_wallets.txt"  # Wallet dengan balance ditemukan
ALL_WALLETS_FILE = "all_wallets.txt" # Semua wallet yang digenerate
LOG_FILE = "btc_scan.log"          # File log aktivitas
CHECKPOINT_FILE = "checkpoint.txt"  # File untuk menyimpan progress

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
    ripemd160 = hashlib.new("ripemd160")
    sha256_hash = hashlib.new("SHA256")
    sha256_hash.update(bytes.fromhex(pubkey_hex))
    ripemd160.update(sha256_hash.digest())
    return base58_check_encode(b"\0", ripemd160.digest())

# ========== GENERASI KEY ==========
def generate_random_key():
    """Generate random private key yang valid (256-bit)"""
    while True:
        try:
            # Gunakan os.urandom untuk keacakan kriptografis
            random_bytes = os.urandom(32)
            key_int = int.from_bytes(random_bytes, byteorder='big')
            
            # Pastikan dalam range valid
            key_int = key_int % MAX_KEY_VALUE
            if key_int == 0:
                key_int = 1
            
            # Konversi ke hex dan pastikan 64 karakter
            hex_key = hex(key_int)[2:].zfill(64)
            if len(hex_key) == 64:
                return key_int, hex_key
        except:
            continue

def generate_sequential_key(start_value):
    """Generate sequential keys untuk testing"""
    current = start_value
    while current <= MAX_KEY_VALUE:
        hex_key = hex(current)[2:].zfill(64)
        if len(hex_key) > 64:
            hex_key = hex_key[-64:]
        yield current, hex_key
        current += 1

# ========== PROCESSING WALLET ==========
def process_key(key_int, hex_key, check_balance=False):
    """Process single key untuk generate wallet Bitcoin"""
    try:
        # 1. Generate WIF (Wallet Import Format)
        compressed_key = base58_check_encode(b"\x80", unhexlify(hex_key), True)
        
        # 2. Generate public key dengan k*G multiplication
        point = g * key_int
        x, y = str(point).split()
        
        # Pad coordinates ke 64 karakter
        x = x.zfill(64)
        y = y.zfill(64)
        
        # 3. Tentukan prefix untuk compressed public key
        pk_prefix = "02" if int(y, 16) % 2 == 0 else "03"
        compressed_public_key = pk_prefix + x
        
        # 4. Generate Bitcoin address
        address = pub_key_to_addr(compressed_public_key)
        
        result = {
            'key_int': key_int,
            'key_hex': hex_key,
            'wif': compressed_key,
            'pubkey': compressed_public_key,
            'address': address,
            'timestamp': datetime.now().isoformat()
        }
        
        # 5. Cek balance jika diperlukan
        if check_balance:
            balance = check_bitcoin_balance(address)
            result['balance'] = balance
            if balance > 0:
                result['has_balance'] = True
        
        return result
        
    except Exception as e:
        log_message(f"Error processing key {key_int}: {e}", "ERROR")
        return None

def check_bitcoin_balance(address):
    """Cek balance Bitcoin address menggunakan blockchain.info"""
    try:
        import urllib.request
        import json
        
        url = f"https://blockchain.info/rawaddr/{address}"
        req = urllib.request.Request(url)
        req.add_header('User-Agent', 'Mozilla/5.0')
        
        response = urllib.request.urlopen(req, timeout=10)
        data = json.loads(response.read().decode('utf-8'))
        
        return data.get('final_balance', 0)
        
    except Exception as e:
        log_message(f"Balance check failed for {address}: {e}", "WARNING")
        return 0

# ========== FILE OPERATIONS ==========
def save_wallet(wallet_data, has_balance=False):
    """Save wallet data ke file yang sesuai"""
    if wallet_data is None:
        return False
    
    try:
        with file_lock:
            # Selalu simpan ke all wallets file
            with open(ALL_WALLETS_FILE, "a", encoding="utf-8") as f:
                f.write(f"{'='*60}\n")
                f.write(f"Key Int: {wallet_data['key_int']}\n")
                f.write(f"Key Hex: {wallet_data['key_hex']}\n")
                f.write(f"WIF: {wallet_data['wif']}\n")
                f.write(f"Public Key: {wallet_data['pubkey']}\n")
                f.write(f"Address: {wallet_data['address']}\n")
                if 'balance' in wallet_data:
                    f.write(f"Balance: {wallet_data['balance']} satoshi\n")
                f.write(f"Time: {wallet_data['timestamp']}\n")
                f.write(f"{'='*60}\n\n")
            
            # Jika ada balance, simpan ke file terpisah
            if has_balance and 'balance' in wallet_data and wallet_data['balance'] > 0:
                with open(RESULTS_FILE, "a", encoding="utf-8") as f:
                    f.write(f"{'#'*80}\n")
                    f.write(f"FOUND WALLET WITH BALANCE!\n")
                    f.write(f"{'#'*80}\n")
                    f.write(f"Key: {wallet_data['key_int']}\n")
                    f.write(f"WIF: {wallet_data['wif']}\n")
                    f.write(f"Address: {wallet_data['address']}\n")
                    f.write(f"Balance: {wallet_data['balance']} satoshi\n")
                    f.write(f"Time: {wallet_data['timestamp']}\n")
                    f.write(f"{'#'*80}\n\n")
                return True
                
        return True
    except Exception as e:
        log_message(f"Error saving wallet: {e}", "ERROR")
        return False

def save_checkpoint(stats):
    """Simpan progress checkpoint"""
    try:
        with open(CHECKPOINT_FILE, "w", encoding="utf-8") as f:
            f.write(f"last_update={datetime.now().isoformat()}\n")
            f.write(f"total_processed={stats['processed']}\n")
            f.write(f"wallets_found={stats['found']}\n")
            f.write(f"total_time={time.time() - stats['start_time']:.2f}\n")
    except:
        pass

def load_checkpoint():
    """Load progress dari checkpoint"""
    stats = {
        'processed': 0,
        'found': 0,
        'start_time': time.time()
    }
    
    try:
        if os.path.exists(CHECKPOINT_FILE):
            with open(CHECKPOINT_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    if '=' in line:
                        key, value = line.strip().split('=')
                        if key == 'total_processed':
                            stats['processed'] = int(value)
                        elif key == 'wallets_found':
                            stats['found'] = int(value)
    except:
        pass
    
    return stats

# ========== DISPLAY & PROGRESS ==========
def display_progress(stats, start_time):
    """Display progress bar dan statistik"""
    elapsed = time.time() - start_time
    processed = stats.get('processed', 0)
    found = stats.get('found', 0)
    
    if processed > 0:
        keys_per_sec = processed / elapsed
    else:
        keys_per_sec = 0
    
    # Progress bar
    bar_length = 40
    progress_percent = min(100, (processed % 1000000) / 10000)  # Reset setiap 1 juta
    
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
        f"Keys: {processed:9,} | "
        f"Found: {found:4,} | "
        f"Speed: {keys_per_sec:6.1f}/s | "
        f"Time: {time_str}"
    )
    
    with print_lock:
        sys.stdout.write(progress_line)
        sys.stdout.flush()

def print_banner():
    """Tampilkan banner program"""
    os.system('clear' if os.name != 'nt' else 'cls')
    
    banner = """
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║  ██████╗  ██████╗ ████████╗ ██████╗ ██████╗  █████╗  ██████╗██╗  ██╗║
║  ██╔══██╗██╔═══██╗╚══██╔══╝██╔═══██╗██╔══██╗██╔══██╗██╔════╝██║ ██╔╝║
║  ██████╔╝██║   ██║   ██║   ██║   ██║██████╔╝███████║██║     █████╔╝ ║
║  ██╔══██╗██║   ██║   ██║   ██║   ██║██╔══██╗██╔══██║██║     ██╔═██╗ ║
║  ██████╔╝╚██████╔╝   ██║   ╚██████╔╝██║  ██║██║  ██║╚██████╗██║  ██╗║
║  ╚═════╝  ╚═════╝    ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝║
║                                                                      ║
║                BITCOIN KEY SCANNER v4.0 - AUTO MODE                  ║
║                Random Bruteforce with k*G Optimization               ║
║                Author: MMDRZA.COM | Threads: {:<3}                    ║
║                                                                      ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  [✓] Mode: Random Scanning                                           ║
║  [✓] Algorithm: k*G elliptic curve multiplication                    ║
║  [✓] Multithreading: {:<3} threads (optimized)                       ║
║  [✓] Batch Size: {:<6}                                              ║
║  [✓] Output: found_wallets.txt & all_wallets.txt                    ║
║                                                                      ║
║  Starting in 3 seconds...                                           ║
║  Press Ctrl+C to stop                                               ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
""".format(MAX_THREADS, MAX_THREADS, BATCH_SIZE)
    
    print(banner)
    
    # Countdown
    for i in range(3, 0, -1):
        print(f"\r  Starting in {i} second{'s' if i > 1 else ''}...{' ' * 20}", end='')
        time.sleep(1)
    
    print("\r" + "=" * 70)
    print(" Scanning started! Random key generation in progress...")
    print("=" * 70)

# ========== MAIN SCANNER ==========
def run_scanner():
    """Main scanner function dengan multithreading"""
    # Tampilkan banner
    print_banner()
    
    # Load checkpoint atau mulai baru
    stats = load_checkpoint()
    if stats['processed'] > 0:
        log_message(f"Resuming from checkpoint: {stats['processed']:,} keys processed", "INFO")
    
    start_time = stats.get('start_time', time.time())
    stats['start_time'] = start_time
    
    # Buat ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        try:
            batch_counter = 0
            last_save = 0
            
            # Main loop - terus berjalan sampai dihentikan
            while True:
                batch_counter += 1
                
                # Generate batch of random keys
                futures = []
                for _ in range(BATCH_SIZE):
                    key_int, hex_key = generate_random_key()
                    # Submit task ke thread pool
                    future = executor.submit(process_key, key_int, hex_key, False)  # Set False untuk tidak cek balance
                    futures.append((future, key_int))
                
                # Process hasil batch
                batch_processed = 0
                batch_found = 0
                
                for future, key_int in futures:
                    try:
                        # Tunggu hasil dengan timeout
                        result = future.result(timeout=30)
                        if result:
                            batch_processed += 1
                            
                            # Save wallet
                            if save_wallet(result):
                                batch_found += 1
                    
                    except Exception as e:
                        log_message(f"Timeout/Error for key {key_int}: {e}", "WARNING")
                        continue
                
                # Update statistik global
                stats['processed'] += batch_processed
                stats['found'] += batch_found
                
                # Tampilkan progress setiap batch
                display_progress(stats, start_time)
                
                # Log progress setiap 10 batch
                if batch_counter % 10 == 0:
                    elapsed = time.time() - start_time
                    keys_per_sec = stats['processed'] / elapsed if elapsed > 0 else 0
                    
                    log_message(
                        f"Batch {batch_counter}: {stats['processed']:,} total keys, "
                        f"Speed: {keys_per_sec:.1f} keys/sec",
                        "INFO"
                    )
                
                # Save checkpoint setiap SAVE_INTERVAL keys
                if stats['processed'] - last_save >= SAVE_INTERVAL:
                    save_checkpoint(stats)
                    last_save = stats['processed']
                
                # Small delay untuk kontrol CPU
                time.sleep(0.01)
                
        except KeyboardInterrupt:
            print("\n\n" + "=" * 70)
            log_message("Scan interrupted by user", "INFO")
            raise
        except Exception as e:
            log_message(f"Scanner error: {e}", "ERROR")
            import traceback
            traceback.print_exc()

# ========== MAIN FUNCTION ==========
def main():
    """Entry point utama"""
    try:
        # Jalankan scanner
        run_scanner()
        
    except KeyboardInterrupt:
        print("\n" + "=" * 70)
        print("SCAN INTERRUPTED")
        print("=" * 70)
    except Exception as e:
        log_message(f"Fatal error: {e}", "CRITICAL")
        import traceback
        traceback.print_exc()
    
    finally:
        # Tampilkan statistik akhir
        print("\n" + "=" * 70)
        print("FINAL STATISTICS")
        print("=" * 70)
        
        # Load statistik terakhir
        stats = load_checkpoint()
        elapsed = time.time() - stats.get('start_time', time.time())
        
        print(f"Total keys processed: {stats.get('processed', 0):,}")
        print(f"Total wallets generated: {stats.get('found', 0):,}")
        print(f"Total time: {elapsed:.2f} seconds")
        
        if stats.get('processed', 0) > 0:
            keys_per_sec = stats['processed'] / elapsed
            print(f"Average speed: {keys_per_sec:.2f} keys/second")
        
        print(f"\nResults saved in:")
        print(f"  - {ALL_WALLETS_FILE} (all generated wallets)")
        print(f"  - {RESULTS_FILE} (wallets with balance - jika ada)")
        print(f"  - {LOG_FILE} (activity log)")
        print("=" * 70)
        
        # Tunggu sebelum exit
        input("\nPress Enter to exit...")

# ========== START PROGRAM ==========
if __name__ == "__main__":
    # Set working directory ke tempat script berada
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    # Jalankan program
    main()
