# proxy_hunter_fonnte.py
"""
Proxy Hunter khusus untuk Fonnte
- Ambil proxy dari beberapa sumber
- Cek HTTP, HTTPS, dan koneksi HTTPS (CONNECT) ke api.fonnte.com
- Simpan yang lolos ke proxy_fonnte_ok.txt
"""

import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import sys
from urllib.parse import urlparse
from tqdm import tqdm

# ---------- CONFIG ----------
SOURCES = [
    ("proxy-list.download (http)", "https://www.proxy-list.download/api/v1/get?type=http"),
    ("proxyscrape (http)", "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all"),
    ("clarketm raw (mixed)", "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt"),
    ("sslproxies (https)", "https://www.sslproxies.org/"),  # fallback parsing below if needed
    ("proxy-list.download (https)", "https://www.proxy-list.download/api/v1/get?type=https")
]
OUT_OK = "proxy_fonnte_ok.txt"
OUT_ALL = "proxies_all.txt"

# Timeouts (detik)
TIMEOUT_HTTP = 6
TIMEOUT_HTTPS = 8
TIMEOUT_FONNTE = 12

# Jumlah thread
WORKERS = 40


# ---------- HELPERS ----------
def fetch_text(url, timeout=10):
    try:
        r = requests.get(url, timeout=timeout, headers={"User-Agent":"Mozilla/5.0"})
        r.raise_for_status()
        return r.text
    except Exception as e:
        # print(f"[!] gagal ambil {url}: {e}")
        return ""

def parse_proxy_lines(text):
    """Ekstrak baris ip:port dari text — cocok untuk banyak sumber yang mengembalikan daftar plain"""
    lines = []
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        # Biasanya sudah ip:port, bisa juga ada protokol di depan
        # Ambil token yang mengandung digit dan ':' minimal satu
        if ":" in s:
            # hilangkan tag html, koma, dsb
            s = s.split()[0].strip().strip(",")
            # jika ada schema http:// atau socks5:// hapus
            parsed = s
            if "://" in parsed:
                parsed = parsed.split("://",1)[1]
            # jika ada "/" trailing, hapus
            parsed = parsed.split("/")[0]
            # terakhir, validasi sederhana ip:port atau host:port
            if parsed.count(":") >= 1:
                lines.append(parsed)
    return lines

def get_from_sslproxies_org():
    """Sedikit parser simple untuk sslproxies.org (table html). Kembalikan ip:port lines."""
    url = "https://www.sslproxies.org/"
    txt = fetch_text(url)
    if not txt:
        return []
    # cari bagian <table id="proxylisttable"> ... rows
    proxies = []
    try:
        start = txt.index('<table')  # crude but ok
        # fallback: ambil semua token yang cocok digit:port
        candidates = []
        for token in txt.replace("<", " ").replace(">", " ").split():
            if token.count(".") >= 1 and ":" in token:
                candidates.append(token)
        proxies = parse_proxy_lines("\n".join(candidates))
    except Exception:
        proxies = parse_proxy_lines(txt)
    return proxies

# ---------- SOURCES COLLECTOR ----------
def collect_proxies():
    out = []
    for name, url in SOURCES:
        # untuk beberapa sumber gunakan metode khusus
        if "sslproxies.org" in url:
            txt = get_from_sslproxies_org()
            out.extend(txt)
            print(f"[+] ambil dari {name}: {len(txt)}")
            continue

        txt = fetch_text(url)
        if not txt:
            print(f"[-] gagal ambil dari {name}")
            continue

        lines = parse_proxy_lines(txt)
        out.extend(lines)
        print(f"[+] ambil dari {name}: {len(lines)}")
    # dedup dan bersihkan
    cleaned = []
    seen = set()
    for p in out:
        p = p.strip()
        if not p:
            continue
        # normalisasi: jika ada user:pass@ip:port -> ambil user:pass@ip:port (biarkan)
        # Hanya skip kalau sudah ada
        if p in seen:
            continue
        seen.add(p)
        cleaned.append(p)
    print(f"[✓] total proxy unik dikumpulkan: {len(cleaned)}")
    # simpan sementara semua
    with open(OUT_ALL, "w", encoding="utf-8") as f:
        for p in cleaned:
            f.write(p + "\n")
    return cleaned

# ---------- CHECK FUNCTIONS ----------
def build_proxy_dict(proxy_raw):
    # Accept formats:
    # - "ip:port"
    # - "http://ip:port"
    # - "https://ip:port"
    # - "socks5://ip:port"
    p = proxy_raw.strip()
    if "://" in p:
        scheme = p.split("://",1)[0].lower()
        host = p.split("://",1)[1]
    else:
        scheme = "http"
        host = p
    # For requests, better pass both http and https keys using http(s) scheme
    proxy_url = f"{scheme}://{host}"
    return {"http": proxy_url, "https": proxy_url}

def test_http(proxy_raw):
    proxies = build_proxy_dict(proxy_raw)
    try:
        r = requests.get("http://httpbin.org/ip", proxies=proxies, timeout=TIMEOUT_HTTP, allow_redirects=True)
        if r.status_code == 200:
            return True
    except Exception:
        pass
    return False

def test_https(proxy_raw):
    proxies = build_proxy_dict(proxy_raw)
    try:
        r = requests.get("https://httpbin.org/ip", proxies=proxies, timeout=TIMEOUT_HTTPS, verify=True)
        if r.status_code == 200:
            return True
    except Exception:
        pass
    return False

def test_fonnte_connect(proxy_raw):
    """
    Test CONNECT ke api.fonnte.com:
    - lakukan GET ke https://api.fonnte.com/  (bukan POST) melalui proxy.
    - Jika proxy mendukung HTTPS CONNECT & tidak di-drop, request akan sampai (200/403/401/302...).
    - Kita hanya periksa apakah koneksi berhasil (status_code returned or no timeout/ProxyError).
    """
    proxies = build_proxy_dict(proxy_raw)
    url = "https://api.fonnte.com/"  # gunakan GET untuk test CONNECT
    headers = {"User-Agent":"Mozilla/5.0", "Accept":"text/html,application/json"}
    try:
        r = requests.get(url, proxies=proxies, timeout=TIMEOUT_FONNTE, headers=headers, verify=True)
        # kalau kita dapat response (apapun) berarti CONNECT berhasil.
        # Return True jika tidak error pada layer koneksi.
        return True
    except Exception as e:
        # return False dan alasan singkat
        return False

def check_proxy_full(proxy_raw):
    """
    Lakukan pemeriksaan berurutan:
    1) HTTP (optional)
    2) HTTPS (wajib)
    3) CONNECT ke api.fonnte.com (wajib)
    Kembalikan tuple (proxy, passed_bool, reason)
    """
    # Normalisasi proxy string
    p = proxy_raw.strip()
    # First quick format validation
    if ":" not in p:
        return (p, False, "invalid_format")

    # 1) optional HTTP test (fast) - kita still check but not mandatory
    http_ok = test_http(p)

    # 2) HTTPS test
    https_ok = test_https(p)
    if not https_ok:
        return (p, False, "no_https")

    # 3) CONNECT to api.fonnte.com
    fonnte_ok = test_fonnte_connect(p)
    if not fonnte_ok:
        return (p, False, "no_fonnte_connect")

    # jika lolos semua
    return (p, True, "ok")

# ---------- MAIN RUN ----------
def main():
    print("Memulai proxy hunter khusus Fonnte...\n")
    proxies = collect_proxies()
    if not proxies:
        print("Tidak ada proxy untuk diperiksa. Keluar.")
        return

    ok_list = []
    bad_list = []

    start = time.time()
    # gunakan ThreadPoolExecutor untuk parallel check
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futures = { ex.submit(check_proxy_full, p): p for p in proxies }
        for fut in tqdm(as_completed(futures), total=len(futures), desc="Checking", unit="p"):
            try:
                p, ok, reason = fut.result()
            except Exception as e:
                # Unexpected error for that proxy
                continue
            if ok:
                ok_list.append(p)
            else:
                bad_list.append((p, reason))

    elapsed = time.time() - start
    print(f"\nSelesai pengecekan dalam {elapsed:.1f}s")
    print(f"[✓] Proxy yang support HTTPS CONNECT ke Fonnte: {len(ok_list)}")
    # simpan hasil
    with open(OUT_OK, "w", encoding="utf-8") as f:
        for p in ok_list:
            f.write(p + "\n")
    # simpan yang gagal juga untuk analisa
    with open("proxy_fonnte_bad.txt", "w", encoding="utf-8") as f:
        for p, reason in bad_list:
            f.write(f"{p}\t{reason}\n")

    print(f"Disimpan ke: {OUT_OK} (dan proxy_fonnte_bad.txt untuk yang gagal)")
    if ok_list:
        print("Contoh proxy yang lolos (5):")
        for p in ok_list[:5]:
            print(" -", p)

if __name__ == "__main__":
    main()
