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
import requests
import json

from utils import g, b58encode

# ========== KONFIGURASI ==========
MAX_THREADS = 12                    # Jumlah thread untuk multithreading
BATCH_SIZE = 5000                   # Ukuran batch processing
CHECK_BALANCE = True               # Aktifkan pengecekan balance
BALANCE_API_TIMEOUT = 5            # Timeout untuk API balance (detik)
SAVE_INTERVAL = 1000               # Simpan progress setiap 1000 wallet

# ========== INISIALISASI ==========
PACKER = Struct(">QQQQ")            # Untuk konversi 256-bit integer
file_lock = threading.Lock()        # Lock untuk thread-safe file operations
print_lock = threading.Lock()       # Lock untuk thread-safe printing

# File output
WALLETS_FILE = "wallets.txt"        # Semua wallet yang digenerate
RICH_WALLETS_FILE = "rich_wallets.txt"  # Wallet dengan balance
LOG_FILE = "scan.log"               # File log aktivitas
PROGRESS_FILE = "progress.txt"      # Progress checkpoint

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
            log_message(f"Address generation failed: {e}", "ERROR")
            return "1ErrorAddress"

# ========== BALANCE CHECKING ==========
def check_balance_simple(address):
    """Cek balance Bitcoin address dengan cara sederhana"""
    try:
        # Gunakan blockchain.info API
        url = f"https://blockchain.info/balance?active={address}"
        headers = {'User-Agent': 'Mozilla/5.0'}
        
        response = requests.get(url, headers=headers, timeout=BALANCE_API_TIMEOUT)
        if response.status_code == 200:
            data = response.json()
            balance = data.get(address, {}).get('final_balance', 0)
            return balance
    except requests.exceptions.Timeout:
        log_message(f"Timeout checking balance for {address}", "WARNING")
    except Exception as e:
        log_message(f"Balance check error: {e}", "WARNING")
    
    return 0

def check_balance_multiple(address):
    """Cek balance dengan multiple API fallback"""
    apis = [
        f"https://blockchain.info/balance?active={address}",
        f"https://api.blockcypher.com/v1/btc/main/addrs/{address}/balance",
        f"https://api.blockchair.com/bitcoin/dashboards/address/{address}"
    ]
    
    for api_url in apis:
        try:
            headers = {'User-Agent': 'Mozilla/5.0'}
            response = requests.get(api_url, headers=headers, timeout=3)
            
            if response.status_code == 200:
                data = response.json()
                
                # Parse response berdasarkan API
                if "blockchain.info" in api_url:
                    balance = data.get(address, {}).get('final_balance', 0)
                elif "blockcypher.com" in api_url:
                    balance = data.get('final_balance', data.get('balance', 0))
                elif "blockchair.com" in api_url:
                    balance = data.get('data', {}).get(address, {}).get('address', {}).get('balance', 0)
                else:
                    continue
                
                if balance > 0:
                    return balance
                    
        except:
            continue
    
    return 0

# ========== WALLET GENERATION ==========
def generate_wallet(key_number):
    """Generate Bitcoin wallet dari number"""
    try:
        # Convert number to hex key (64 karakter)
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
        if CHECK_BALANCE:
            balance = check_balance_simple(address)
        
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
        log_message(f"Error generating wallet for {key_number}: {e}", "ERROR")
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
                num = futures[future]
                log_message(f"Timeout/Error for {num}: {e}", "WARNING")
    
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
                    f.write(f"💰 WALLET DENGAN SALDO DITEMUKAN! 💰\n")
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
                
                return True  # Menandakan ditemukan wallet dengan saldo
        
        return False
        
    except Exception as e:
        log_message(f"Error saving wallet: {e}", "ERROR")
        return False

# ========== DISPLAY PROGRESS ==========
def display_progress(stats, start_time):
    """Display progress bar dan statistik real-time"""
    elapsed = time.time() - start_time
    processed = stats.get('processed', 0)
    rich_found = stats.get('rich_found', 0)
    
    if processed > 0:
        keys_per_sec = processed / elapsed
    else:
        keys_per_sec = 0
    
    # Progress bar
    bar_length = 40
    progress_percent = min(100, (processed % 1000000) / 10000)
    
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
║                BITCOIN WALLET SCANNER v2.0                          ║
║                Multithreaded + Balance Check                        ║
║                Author: MMDRZA.COM                                   ║
║                                                                      ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  [✓] Mode: Random Scanning                                           ║
║  [✓] Multithreading: {:<3} threads                                   ║
║  [✓] Balance Checking: {:<10}                                       ║
║  [✓] Batch Size: {:<6}                                              ║
║                                                                      ║
║  Output Files:                                                       ║
║    - wallets.txt (all wallets)                                       ║
║    - rich_wallets.txt (wallets with balance)                         ║
║                                                                      ║
║  Press Ctrl+C to stop                                               ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
""".format(
    MAX_THREADS,
    "ENABLED" if CHECK_BALANCE else "DISABLED",
    BATCH_SIZE
)
    
    print(banner)
    print("\n" + "=" * 70)
    print("Starting random wallet generation with balance checking...")
    print("=" * 70)

# ========== MAIN SCANNER ==========
def main_scanner():
    """Main scanner function dengan multithreading"""
    # Tampilkan banner
    print_banner()
    
    # Load progress jika ada
    wallets_generated = load_progress()
    log_message(f"Resuming from {wallets_generated:,} wallets generated", "INFO")
    
    # Inisialisasi stats
    stats = {
        'processed': wallets_generated,
        'rich_found': 0,
        'start_time': time.time(),
        'last_save': wallets_generated
    }
    
    # Cek file rich wallets sebelumnya
    if os.path.exists(RICH_WALLETS_FILE):
        try:
            with open(RICH_WALLETS_FILE, "r", encoding="utf-8") as f:
                content = f.read()
                rich_count = content.count("WALLET DENGAN SALDO DITEMUKAN")
                stats['rich_found'] = rich_count
        except:
            pass
    
    try:
        batch_counter = 0
        
        while True:
            batch_counter += 1
            
            # Generate batch of random numbers
            batch_numbers = []
            for _ in range(BATCH_SIZE):
                # Generate random number dalam range yang luas
                random_num = random.randint(1, 10**30)
                batch_numbers.append(random_num)
            
            # Process batch dengan multithreading
            log_message(f"Processing batch {batch_counter}...", "INFO")
            batch_results = process_batch(batch_numbers)
            
            # Process results
            batch_rich = 0
            for result in batch_results:
                stats['processed'] += 1
                
                # Save wallet
                if save_wallet_result(result):
                    batch_rich += 1
                    stats['rich_found'] += 1
                    
                    # Tampilkan alert untuk wallet dengan saldo
                    with print_lock:
                        print(f"\n\n{'!'*80}")
                        print(f"💰 WALLET DENGAN SALDO DITEMUKAN! 💰")
                        print(f"Address: {result['address']}")
                        print(f"Balance: {result['balance']} satoshi")
                        print(f"{'!'*80}\n")
            
            # Tampilkan progress
            display_progress(stats, stats['start_time'])
            
            # Log progress setiap 5 batch
            if batch_counter % 5 == 0:
                elapsed = time.time() - stats['start_time']
                keys_per_sec = stats['processed'] / elapsed if elapsed > 0 else 0
                
                log_message(
                    f"Progress: {stats['processed']:,} wallets | "
                    f"Rich found: {stats['rich_found']:,} | "
                    f"Speed: {keys_per_sec:.1f} wallets/sec",
                    "INFO"
                )
            
            # Save progress setiap SAVE_INTERVAL
            if stats['processed'] - stats['last_save'] >= SAVE_INTERVAL:
                save_progress(stats['processed'], stats['start_time'])
                stats['last_save'] = stats['processed']
            
            # Small delay untuk kontrol CPU
            time.sleep(0.01)
            
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
        # Jalankan scanner
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
        # Tampilkan statistik akhir
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
        
        # Hitung rasio
        if processed > 0:
            ratio = (rich_found / processed) * 100
            print(f"Success ratio: {ratio:.6f}%")
        
        print(f"\nResults saved in:")
        print(f"  - {WALLETS_FILE} (all wallets)")
        if rich_found > 0:
            print(f"  - {RICH_WALLETS_FILE} (wallets with balance)")
        print(f"  - {LOG_FILE} (activity log)")
        print("=" * 70)
        
        # Simpan progress terakhir
        save_progress(processed, final_stats.get('start_time', time.time()))
        
        # Tunggu sebelum exit
        input("\nPress Enter to exit...")

# ========== START PROGRAM ==========
if __name__ == "__main__":
    # Set working directory ke tempat script berada
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    # Jalankan program
    main()
