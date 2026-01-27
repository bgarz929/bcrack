import os
import sys
import time
import random
import threading
import hashlib
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed, ProcessPoolExecutor
from binascii import hexlify, unhexlify
from struct import Struct
import asyncio
import base58
import bech32
import multiprocessing
import ssl
from aiorpcx import connect_rs
import socket

from utils import g, b58encode

# ========== KONFIGURASI ==========
MAX_THREADS = 12                    # Jumlah thread untuk multithreading
BATCH_SIZE = 5000                   # Ukuran batch processing
CHECK_BALANCE = True               # Aktifkan pengecekan balance
SAVE_INTERVAL = 1000               # Simpan progress setiap 1000 wallet
USE_ELECTRUM_API = True            # Gunakan Electrum API yang lebih cepat
ELECTRUM_MAX_CONCURRENT = 8        # Koneksi concurrent ke Electrum
USE_MULTIPROCESSING = True         # Gunakan multiprocessing untuk balance check
MAX_RETRIES = 3                    # Maksimal retry untuk koneksi Electrum
CONNECTION_TIMEOUT = 10            # Timeout koneksi Electrum (detik)

# ========== INISIALISASI ==========
PACKER = Struct(">QQQQ")            # Untuk konversi 256-bit integer
file_lock = threading.Lock()        # Lock untuk thread-safe file operations
print_lock = threading.Lock()       # Lock untuk thread-safe printing

# File output
WALLETS_FILE = "wallets.txt"        # Semua wallet yang digenerate
RICH_WALLETS_FILE = "rich_wallets.txt"  # Wallet dengan balance
LOG_FILE = "scan.log"               # File log aktivitas
PROGRESS_FILE = "progress.txt"      # Progress checkpoint

# ========== ELECTRUM SERVER LIST (DIPERBARUI) ==========
ELECTRUM_SERVERS = [
    {"host": "electrumx-core.1209k.com", "port": 50002, "protocol": "ssl"},
    {"host": "bitcoin.aranguren.org", "port": 50002, "protocol": "ssl"},
    {"host": "electrum.loyce.club", "port": 50002, "protocol": "ssl"},
    {"host": "fulcrum.slicksparks.ky", "port": 50002, "protocol": "ssl"},
    {"host": "electrum.kampfschnitzel.at", "port": 50002, "protocol": "ssl"},
    {"host": "electrum.sare.red", "port": 50002, "protocol": "ssl"},
    {"host": "blackie.c3-soft.com", "port": 57002, "protocol": "ssl"},
    {"host": "fulcrum2.not.fyi", "port": 51002, "protocol": "ssl"},
    {"host": "electrum.cakewallet.com", "port": 50002, "protocol": "ssl"},
    {"host": "molten.tranquille.cc", "port": 50002, "protocol": "ssl"},
    {"host": "clownshow.fiatfaucet.com", "port": 50002, "protocol": "ssl"},
    {"host": "btc.electroncash.dk", "port": 60002, "protocol": "ssl"},
    {"host": "tool.sh", "port": 50002, "protocol": "ssl"},
    {"host": "fulcrum.bitcoinrocks.net", "port": 50002, "protocol": "ssl"},
    {"host": "electrum.qtornado.com", "port": 50002, "protocol": "ssl"},
    {"host": "electrum.blockstream.info", "port": 50002, "protocol": "ssl"},
    {"host": "electrum.emzy.de", "port": 50002, "protocol": "ssl"},
    {"host": "electrum.hodlister.co", "port": 50002, "protocol": "ssl"},
    {"host": "electrum.villocq.com", "port": 50002, "protocol": "ssl"},
    {"host": "electrumx.bot.nu", "port": 50002, "protocol": "ssl"},
]

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

# ========== ELECTRUM UTILITIES ==========
def address_to_scripthash(address: str) -> str:
    """Convert Bitcoin address to script hash for Electrum API"""
    try:
        # Untuk address Bech32 (segwit v0) dan Bech32m (Taproot/segwit v1)
        if address.startswith("bc1") or address.startswith("tb1"):
            if address.startswith("bc1"):
                hrp = "bc"
            else:
                hrp = "tb"
            
            try:
                witver, witprog = bech32.decode(hrp, address)
            except Exception as e:
                raise ValueError(f"Failed to decode bech32 address: {e}")
            
            if witver is None or witprog is None:
                raise ValueError("Invalid bech32/bech32m address")
            
            # Konversi witver/witprog ke script
            if witver == 0:
                if len(witprog) == 20:
                    script = bytes([0x00, 0x14]) + bytes(witprog)
                elif len(witprog) == 32:
                    script = bytes([0x00, 0x20]) + bytes(witprog)
                else:
                    raise ValueError(f"Invalid witness program length for segwit v0: {len(witprog)}")
            elif witver == 1:
                if len(witprog) == 32:
                    script = bytes([0x51, 0x20]) + bytes(witprog)
                else:
                    raise ValueError(f"Invalid witness program length for Taproot: {len(witprog)}")
            else:
                if 2 <= len(witprog) <= 40:
                    script = bytes([0x50 + witver, len(witprog)]) + bytes(witprog)
                else:
                    raise ValueError(f"Unsupported witness version: {witver}")
        else:  # Base58 addresses
            decoded = base58.b58decode_check(address)
            ver, payload = decoded[0], decoded[1:]
            if ver == 0x00:  # P2PKH
                script = b"\x76\xa9\x14" + payload + b"\x88\xac"
            elif ver == 0x05:  # P2SH
                script = b"\xa9\x14" + payload + b"\x87"
            else:
                raise ValueError("unknown address version")
        
        # Script hash untuk Electrum (SHA256 lalu reverse)
        scripthash = hashlib.sha256(script).digest()[::-1].hex()
        return scripthash
    except Exception as e:
        raise ValueError(f"address_to_scripthash error for {address}: {e}")

def create_ssl_context():
    """Create SSL context untuk koneksi Electrum"""
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    ssl_context.options |= ssl.OP_ALL
    ssl_context.set_ciphers('DEFAULT@SECLEVEL=1')
    return ssl_context

async def check_server_health(server_info):
    """Cek kesehatan server Electrum"""
    try:
        ssl_context = create_ssl_context()
        async with connect_rs(
            server_info["host"], 
            server_info["port"], 
            ssl=ssl_context,
            timeout=CONNECTION_TIMEOUT
        ) as session:
            # Test connection dengan request sederhana
            version = await session.send_request("server.version", ["electrum-client", "1.4"])
            if version:
                return True
    except (asyncio.TimeoutError, ConnectionError, socket.error) as e:
        log_message(f"Server {server_info['host']}:{server_info['port']} tidak sehat: {e}", "WARNING")
    except Exception as e:
        log_message(f"Error checking server {server_info['host']}:{server_info['port']}: {e}", "WARNING")
    return False

async def get_healthy_servers():
    """Dapatkan server yang sehat"""
    healthy_servers = []
    tasks = []
    
    for server in ELECTRUM_SERVERS:
        task = asyncio.create_task(check_server_health(server))
        tasks.append((server, task))
    
    for server, task in tasks:
        try:
            is_healthy = await asyncio.wait_for(task, timeout=CONNECTION_TIMEOUT)
            if is_healthy:
                healthy_servers.append(server)
        except asyncio.TimeoutError:
            continue
    
    if not healthy_servers:
        raise Exception("Tidak ada server Electrum yang sehat!")
    
    log_message(f"Ditemukan {len(healthy_servers)} server Electrum yang sehat", "INFO")
    return healthy_servers

async def check_balance_electrum_with_retry(address, server_info, retries=MAX_RETRIES):
    """Check balance menggunakan Electrum protocol dengan retry mechanism"""
    for attempt in range(retries):
        try:
            ssl_context = create_ssl_context()
            async with connect_rs(
                server_info["host"], 
                server_info["port"], 
                ssl=ssl_context,
                timeout=CONNECTION_TIMEOUT
            ) as session:
                # Get script hash
                scripthash = address_to_scripthash(address)
                
                # Request balance
                result = await asyncio.wait_for(
                    session.send_request("blockchain.scripthash.get_balance", [scripthash]),
                    timeout=CONNECTION_TIMEOUT
                )
                
                if isinstance(result, dict):
                    confirmed = result.get("confirmed", 0)
                    unconfirmed = result.get("unconfirmed", 0)
                    total_satoshis = confirmed + unconfirmed
                    return total_satoshis
                else:
                    return 0
                    
        except (asyncio.TimeoutError, ConnectionError, socket.error) as e:
            if attempt < retries - 1:
                await asyncio.sleep(1 * (attempt + 1))  # Exponential backoff
                continue
            else:
                log_message(f"Gagal koneksi ke {server_info['host']}:{server_info['port']} setelah {retries} percobaan: {e}", "WARNING")
                return 0
        except Exception as e:
            log_message(f"Error checking balance untuk {address}: {e}", "WARNING")
            return 0
    
    return 0

async def check_balances_batch_electrum(addresses, server_info):
    """Check batch of addresses menggunakan Electrum"""
    results = {}
    
    for address in addresses:
        balance = await check_balance_electrum_with_retry(address, server_info)
        results[address] = balance
    
    return results

def check_balances_multiprocess(address_batch):
    """Check balances menggunakan multiprocessing"""
    if not CHECK_BALANCE or not USE_ELECTRUM_API or not address_batch:
        return {addr: 0 for addr in address_batch}
    
    try:
        # Inisialisasi server manager di process ini
        async def init_server_manager():
            healthy_servers = await get_healthy_servers()
            if not healthy_servers:
                raise Exception("No healthy servers available")
            return random.choice(healthy_servers)
        
        # Dapatkan server yang sehat
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        server = loop.run_until_complete(init_server_manager())
        loop.close()
        
        # Check balances dengan server yang sehat
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(check_balances_batch_electrum(address_batch, server))
        loop.close()
        
        return results
    except Exception as e:
        log_message(f"Multiprocess balance check error: {e}", "ERROR")
        return {addr: 0 for addr in address_batch}

# ========== BALANCE CHECKING (ELECTRUM ONLY) ==========
def check_balance_electrum_only(address):
    """Cek balance Bitcoin address HANYA dengan Electrum"""
    if not CHECK_BALANCE or not USE_ELECTRUM_API:
        return 0
    
    try:
        # Dapatkan server yang sehat terlebih dahulu
        async def get_server_and_check():
            healthy_servers = await get_healthy_servers()
            if not healthy_servers:
                return 0
            
            server = random.choice(healthy_servers)
            return await check_balance_electrum_with_retry(address, server)
        
        # Buat event loop baru untuk thread ini
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        balance = loop.run_until_complete(get_server_and_check())
        loop.close()
        
        return balance
        
    except Exception as e:
        log_message(f"Electrum balance check failed for {address}: {e}", "WARNING")
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
        
        # 4. Cek Balance jika diaktifkan (HANYA ELECTRUM)
        balance = 0
        if CHECK_BALANCE:
            balance = check_balance_electrum_only(address)
        
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
    
    # Jika balance checking diaktifkan dan menggunakan Electrum dengan multiprocessing
    if CHECK_BALANCE and USE_ELECTRUM_API and USE_MULTIPROCESSING and len(batch_numbers) > 1:
        try:
            # Generate semua wallet terlebih dahulu
            wallets = []
            for num in batch_numbers:
                wallet = generate_wallet(num)
                if wallet:
                    wallets.append(wallet)
            
            # Check balances dalam batch menggunakan Electrum dengan multiprocessing
            if wallets:
                addresses = [w['address'] for w in wallets]
                
                # Gunakan multiprocessing untuk balance check
                with ProcessPoolExecutor(max_workers=min(4, multiprocessing.cpu_count())) as executor:
                    # Split addresses into chunks
                    chunk_size = max(10, len(addresses) // 4)
                    chunks = [addresses[i:i + chunk_size] for i in range(0, len(addresses), chunk_size)]
                    
                    # Submit chunks for processing
                    future_to_chunk = {
                        executor.submit(check_balances_multiprocess, chunk): chunk 
                        for chunk in chunks
                    }
                    
                    # Collect results
                    balance_results = {}
                    for future in as_completed(future_to_chunk):
                        chunk_results = future.result()
                        balance_results.update(chunk_results)
                
                # Update wallet balances
                for wallet in wallets:
                    wallet['balance'] = balance_results.get(wallet['address'], 0)
                
                results.extend(wallets)
            else:
                results = []
        
        except Exception as e:
            log_message(f"Batch processing error: {e}, falling back to single mode...", "ERROR")
            # Fallback ke threading biasa
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
    else:
        # Proses normal tanpa optimisasi batch
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
    
    banner = f"""
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║  ██████  ██████  ████████ ██████  ██████  ██ ███    ██ ██████   ║
║  ██   ██ ██   ██    ██    ██   ██ ██   ██ ██ ████   ██ ██   ██  ║
║  ██████  ██████     ██    ██████  ██████  ██ ██ ██  ██ ██   ██  ║
║  ██   ██ ██   ██    ██    ██      ██   ██ ██ ██  ██ ██ ██   ██  ║
║  ██████  ██   ██    ██    ██      ██   ██ ██ ██   ████ ██████   ║
║                                                                  ║
║               BITCOIN WALLET SCANNER v2.3                        ║
║           Pure Electrum Balance Check (No Fallback)              ║
║               Author: MMDRZA.COM                                 ║
║                                                                  ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  [✓] Mode: Random Scanning                                       ║
║  [✓] Multithreading: {MAX_THREADS:<3} threads                                   ║
║  [✓] Balance Checking: PURE ELECTRUM ONLY                        ║
║  [✓] Electrum Servers: {len(ELECTRUM_SERVERS):<3} (health checked)               ║
║  [✓] Batch Size: {BATCH_SIZE:<6}                                              ║
║  [✓] Multiprocessing: {("ENABLED" if USE_MULTIPROCESSING else "DISABLED"):<10}                ║
║  [✓] Max Retries: {MAX_RETRIES:<3}                                            ║
║  [✓] Connection Timeout: {CONNECTION_TIMEOUT}s                                 ║
║                                                                  ║
║  Output Files:                                                   ║
║    - wallets.txt (all wallets)                                   ║
║    - rich_wallets.txt (wallets with balance)                     ║
║                                                                  ║
║  Press Ctrl+C to stop                                           ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
"""
    
    print(banner)
    print("\n" + "=" * 70)
    print("Starting random wallet generation with PURE Electrum balance checking...")
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
                        print(f"🎯 WALLET DENGAN SALDO DITEMUKAN! 🎯")
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
