# -*- coding: utf-8 -*-
import sys, os

# Windows CP1252 fix — must be before any print()
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import requests
import json
import time
import base64
import socket
import subprocess
import tempfile
import re
import statistics
from urllib.parse import urlparse, urlunparse, quote, unquote, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

# =====================
# GITHUB
# =====================
GITHUB_TOKEN  = os.getenv('GH_TOKEN')
GITHUB_REPO   = 'ANAEHY/SPECTER'
GITHUB_FILE   = 'keys.txt'
GITHUB_BRANCH = 'main'

HEADER = """#profile-title: base64:8J+RuyBTUEFDVEVSIFZQTg==
#profile-update-interval: 12"""

# =====================
# COUNTRY MAPS
# =====================
COUNTRY_RU = {
    "🇩🇪": "Германия",  "🇫🇷": "Франция",    "🇳🇱": "Нидерланды", "🇮🇹": "Италия",
    "🇪🇸": "Испания",   "🇵🇱": "Польша",      "🇧🇪": "Бельгия",    "🇦🇹": "Австрия",
    "🇨🇭": "Швейцария", "🇸🇪": "Швеция",      "🇳🇴": "Норвегия",   "🇩🇰": "Дания",
    "🇫🇮": "Финляндия", "🇬🇧": "Британия",    "🇺🇸": "США",        "🇨🇦": "Канада",
    "🇦🇺": "Австралия", "🇯🇵": "Япония",       "🇰🇷": "Корея",      "🇸🇬": "Сингапур",
    "🇷🇺": "Россия",    "🇺🇦": "Украина",      "🇹🇷": "Турция",     "🇮🇱": "Израиль",
    "🇦🇪": "ОАЭ",       "🇮🇳": "Индия",        "🇧🇷": "Бразилия",   "🌐": "Anycast",
}

# =====================
# XRAY
# =====================
XRAY_PATH = 'xray.exe' if os.name == 'nt' else '/tmp/xray'

def install_xray() -> bool:
    if os.path.exists(XRAY_PATH):
        return True
    try:
        if os.name == 'nt':
            url = 'https://github.com/XTLS/Xray-core/releases/download/v1.8.6/Xray-windows-64.zip'
            r   = requests.get(url, timeout=60, stream=True)
            with open('xray.zip', 'wb') as f:
                for c in r.iter_content(8192): f.write(c)
            import zipfile
            with zipfile.ZipFile('xray.zip') as z: z.extractall('.')
            os.remove('xray.zip')
        else:
            r   = requests.get('https://api.github.com/repos/XTLS/Xray-core/releases/latest', timeout=15)
            ver = r.json()['tag_name']
            url = f'https://github.com/XTLS/Xray-core/releases/download/{ver}/Xray-linux-64.zip'
            r   = requests.get(url, timeout=60, stream=True)
            with open('/tmp/xray.zip', 'wb') as f:
                for c in r.iter_content(8192): f.write(c)
            import zipfile
            with zipfile.ZipFile('/tmp/xray.zip') as z: z.extract('xray', '/tmp/')
            os.chmod(XRAY_PATH, 0o755)
            os.remove('/tmp/xray.zip')
        return True
    except Exception as e:
        print(f"[XRAY install error] {e}")
        return False

# ─────────────────────────────────────────────
#  ГЛАВНЫЙ ФИЛЬТР
#  Критерии братишка:
#    ✓ протокол = vless
#    ✓ security = reality
#    ✓ type     = tcp
#    ✓ pbk      = есть (публичный ключ)
#    — fp, sni  = не важны, принимаем любые
# ─────────────────────────────────────────────
def is_valid_key(uri: str) -> bool:
    try:
        p = urlparse(uri)
        if p.scheme != 'vless':
            return False
        q   = parse_qs(p.query)
        sec = q.get('security', [''])[0].lower()
        net = q.get('type',     ['tcp'])[0].lower()  # если type не указан — TCP по умолчанию
        pbk = q.get('pbk',      [''])[0].strip()
        return sec == 'reality' and net == 'tcp' and len(pbk) > 0
    except Exception:
        return False

# =====================
# PRE-FILTER
# =====================
BAD_IP_PREFIXES   = ('104.', '172.6', '172.7', '188.114.', '162.158.', '198.41.')
BAD_HOST_PATTERNS = ('workers.dev', 'pages.dev', 'cloudflare', 'fastly.net')
BAD_ASN_ORGS      = ('cloudflare', 'fastly', 'akamai', 'incapsula', 'imperva')

GENERATE_204_URLS = [
    'https://www.gstatic.com/generate_204',
    'https://www.google.com/generate_204',
    'https://cp.cloudflare.com/generate_204',
]

def quick_filter(uri: str) -> tuple[bool, str]:
    """DNS + IP до запуска xray — быстрый отсев."""
    try:
        host = (urlparse(uri).hostname or '').lower()
        if not host:
            return False, 'empty host'
        for pat in BAD_HOST_PATTERNS:
            if pat in host:
                return False, f'bad host: {pat}'
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            return False, 'DNS fail'
        for prefix in BAD_IP_PREFIXES:
            if ip.startswith(prefix):
                return False, f'CF IP: {prefix}'
        return True, ip
    except Exception as e:
        return False, str(e)

# =====================
# VLESS → XRAY CONFIG
# =====================
def parse_vless(uri: str) -> dict | None:
    """
    Строим outbound для xray.
    Для REALITY+TCP выставляем явный tcpSettings.
    fp и sni берём как есть — не фильтруем.
    """
    try:
        p    = urlparse(uri)
        q    = parse_qs(p.query)
        h    = p.hostname
        pt   = p.port or 443
        u    = p.username
        flow = q.get('flow', [''])[0]
        sni  = q.get('sni',  [h])[0]
        fp   = q.get('fp',   ['chrome'])[0]   # любой fingerprint
        pbk  = q.get('pbk',  [''])[0]
        sid  = q.get('sid',  [''])[0]

        return {
            'protocol': 'vless',
            'settings': {
                'vnext': [{
                    'address': h,
                    'port':    pt,
                    'users':   [{'id': u, 'encryption': 'none', 'flow': flow}],
                }]
            },
            'streamSettings': {
                'network':  'tcp',
                'security': 'reality',
                'realitySettings': {
                    'serverName':  sni,
                    'fingerprint': fp,
                    'publicKey':   pbk,
                    'shortId':     sid,
                },
                'tcpSettings': {},
            },
        }
    except Exception:
        return None

def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

# =====================
# ПАРАЛЛЕЛЬНЫЙ 204
# =====================
def check_204_parallel(proxies: dict, timeout: float = 4.0) -> list[float]:
    """
    Шлём GET к 3 generate_204 URL одновременно.
    Нужно >= 2 ответов HTTP 204 — тогда ключ живой.
    """
    latencies = []

    def fetch_one(url: str) -> float | None:
        try:
            t0 = time.time()
            r  = requests.get(url, proxies=proxies, timeout=timeout, allow_redirects=False)
            ms = round((time.time() - t0) * 1000, 1)
            return ms if r.status_code == 204 else None
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=3) as ex:
        for f in as_completed([ex.submit(fetch_one, u) for u in GENERATE_204_URLS]):
            r = f.result()
            if r is not None:
                latencies.append(r)

    return latencies

# =====================
# IP / ASN
# =====================
def check_real_ip(proxies: dict, timeout: float = 5.0) -> tuple[bool, str]:
    """Два независимых сервиса должны вернуть один IP."""
    ips = []
    for url in ['https://api.ipify.org', 'https://ifconfig.me/ip']:
        try:
            r  = requests.get(url, proxies=proxies, timeout=timeout)
            ip = r.text.strip()
            if ip and re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                ips.append(ip)
        except Exception:
            continue
    if len(ips) < 2:
        return True, ips[0] if ips else 'unknown'
    if ips[0] != ips[1]:
        return False, f'balancer: {ips[0]} != {ips[1]}'
    for prefix in BAD_IP_PREFIXES:
        if ips[0].startswith(prefix):
            return False, f'CF IP: {ips[0]}'
    return True, ips[0]

def check_asn(proxies: dict, timeout: float = 5.0) -> tuple[bool, str]:
    """CDN ASN → reject."""
    try:
        r   = requests.get('https://ipinfo.io/json', proxies=proxies, timeout=timeout)
        org = r.json().get('org', '').lower()
        for bad in BAD_ASN_ORGS:
            if bad in org:
                return False, org
        return True, org
    except Exception:
        return True, 'unknown'

# =====================
# XRAY CHECK
# =====================
def check_xray(uri: str, timeout: float = 8.0) -> float:
    """
    Полная проверка одного ключа через xray:
      1. quick_filter  — DNS/IP предфильтр
      2. parse_vless   — строим конфиг
      3. xray SOCKS5   — поднимаем локальный прокси
      4. 204 x3        — параллельно, нужно >= 2
      5. jitter <= 80ms
      6. real IP       — два сервиса совпадают
      7. ASN           — не CDN

    Возвращает score (меньше = лучше) или 9999 при провале.
    """
    host = urlparse(uri).hostname or ''

    # 1. Pre-filter
    ok, ip_or_err = quick_filter(uri)
    if not ok:
        print(f"      [SKIP] {host}: {ip_or_err}")
        return 9999

    # 2. Parse
    outbound = parse_vless(uri)
    if not outbound:
        print(f"      [SKIP] parse fail: {host}")
        return 9999

    port = get_free_port()
    cfg  = {
        'log':       {'loglevel': 'none'},
        'inbounds':  [{'port': port, 'listen': '127.0.0.1',
                       'protocol': 'socks',
                       'settings': {'auth': 'noauth', 'udp': True}}],
        'outbounds': [outbound, {'protocol': 'freedom', 'tag': 'direct'}],
    }

    tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
    json.dump(cfg, tmp); tmp.close()

    err_log = tempfile.NamedTemporaryFile(
        mode='w', suffix='.err', delete=False, encoding='utf-8')
    err_log.close()

    proc = None
    try:
        # 3. Start xray
        proc = subprocess.Popen(
            [XRAY_PATH, 'run', '-c', tmp.name],
            stdout=subprocess.DEVNULL,
            stderr=open(err_log.name, 'w', encoding='utf-8'),
        )

        # Wait for SOCKS port to open (up to 5s) instead of blind sleep
        deadline = time.time() + 5.0
        port_up  = False
        while time.time() < deadline:
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                    port_up = True
                    break
            except OSError:
                time.sleep(0.15)

        if not port_up:
            try:
                xray_err = open(err_log.name, encoding='utf-8',
                                errors='replace').read(400).strip()
                if xray_err:
                    print(f'      [XRAY ERR] {host}: {xray_err[:200]}')
            except Exception:
                pass
            print(f'      [SKIP] port not up: {host}')
            return 9999

        proxies = {
            'http':  f'socks5h://127.0.0.1:{port}',
            'https': f'socks5h://127.0.0.1:{port}',
        }

        # 4. 204 параллельно
        latencies = check_204_parallel(proxies, timeout=timeout)
        if len(latencies) < 2:
            print(f"      [SKIP] 204 fail ({len(latencies)}/3): {host}")
            return 9999

        avg    = statistics.mean(latencies)
        jitter = max(latencies) - min(latencies)
        print(f"      [204 OK] {host}  avg={avg:.0f}ms  jitter={jitter:.0f}ms")

        # 5. Jitter
        if jitter > 80:
            print(f"      [SKIP] jitter {jitter:.0f}ms > 80ms")
            return 9999

        # 6. Реальный IP
        ip_ok, ip_info = check_real_ip(proxies, timeout=5.0)
        if not ip_ok:
            print(f"      [SKIP] IP: {ip_info}")
            return 9999
        print(f"      [IP]  {ip_info}")

        # 7. ASN
        asn_ok, org = check_asn(proxies, timeout=5.0)
        if not asn_ok:
            print(f"      [SKIP] ASN: {org}")
            return 9999
        print(f"      [ASN] {org}")

        score = round(avg + jitter * 0.5 - 100, 1)   # -100 бонус за REALITY
        print(f"      [PASS] score={score}")
        return score

    except Exception as e:
        print(f"      [ERR] {host}: {e}")
        return 9999
    finally:
        if proc:
            try: proc.kill(); proc.wait(timeout=2)
            except Exception: pass
        try: os.unlink(tmp.name)
        except Exception: pass
        try: os.unlink(err_log.name)
        except Exception: pass
        try: os.unlink(err_log.name)
        except Exception: pass

# =====================
# PARALLEL CHECK
# =====================
def check_all(keys: list[str], workers: int = 10) -> list[tuple[str, float]]:
    results = []

    def worker(uri):
        score = check_xray(uri)
        return (uri, score) if score < 9999 else (None, 9999)

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(worker, k): k for k in keys}
        done = alive = 0
        for future in as_completed(futures):
            uri, score = future.result()
            done += 1
            if uri:
                results.append((uri, score))
                alive += 1
            if done % 10 == 0 or done == len(keys):
                print(f"   [{done}/{len(keys)}] alive: {alive}", flush=True)

    results.sort(key=lambda x: x[1])
    return results

# =====================
# COUNTRY DETECTION
# =====================
def get_flag_and_country(fragment: str) -> tuple[str, str]:
    decoded = unquote(fragment)
    m       = re.search(r'([\U0001F1E0-\U0001F1FF]{2})', decoded)
    if m and m.group(1) in COUNTRY_RU:
        return m.group(1), COUNTRY_RU[m.group(1)]
    return "🌐", "Anycast"

def extract_country(config: str) -> str:
    patterns = {
        'DE': ['de-','germany','berlin','frankfurt'],
        'FR': ['fr-','france','paris'],
        'NL': ['nl-','netherlands','amsterdam','rotterdam'],
        'IT': ['it-','italy','rome','milan'],
        'ES': ['es-','spain','madrid'],
        'PL': ['pl-','poland','warsaw'],
        'GB': ['gb-','uk','london','britain','england'],
        'US': ['us-','usa','new york','nyc'],
        'CA': ['ca-','canada','toronto'],
        'JP': ['jp-','japan','tokyo'],
        'RU': ['ru-','russia','moscow','spb'],
    }
    cfg = config.lower()
    for country, pats in patterns.items():
        if any(p in cfg for p in pats):
            return country
    return 'OTHER'

def get_country_from_url(uri: str) -> tuple[str, str]:
    flag, country = get_flag_and_country(urlparse(uri).fragment)
    if country != "Anycast":
        return flag, country
    code_map = {
        'DE':('🇩🇪','Германия'),  'NL':('🇳🇱','Нидерланды'),
        'FR':('🇫🇷','Франция'),   'IT':('🇮🇹','Италия'),
        'ES':('🇪🇸','Испания'),   'PL':('🇵🇱','Польша'),
        'GB':('🇬🇧','Британия'),  'US':('🇺🇸','США'),
        'CA':('🇨🇦','Канада'),    'AU':('🇦🇺','Австралия'),
        'JP':('🇯🇵','Япония'),    'KR':('🇰🇷','Корея'),
        'RU':('🇷🇺','Россия'),
    }
    return code_map.get(extract_country(uri), ("🌐", "Anycast"))

def rename_with_country(uri: str, lte: bool) -> str:
    p             = urlparse(uri)
    flag, country = get_country_from_url(uri)
    tag           = "LTE" if lte else "WiFi"
    return urlunparse((p.scheme, p.netloc, p.path, p.params,
                       p.query, quote(f"{flag} {country} - {tag}")))

# =====================
# SOURCES
# =====================
IGARECK_SOURCES = [
    {'url': 'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS_mobile.txt',               'lte': False, 'top_n': 8},
    {'url': 'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt',                      'lte': False, 'top_n': 8},
    {'url': 'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile.txt',  'lte': True,  'top_n': 8},
    {'url': 'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile-2.txt','lte': True,  'top_n': 8},
    {'url': 'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/WHITE-CIDR-RU-checked.txt',                'lte': True,  'top_n': 8},
    {'url': 'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/WHITE-SNI-RU-all.txt',                     'lte': True,  'top_n': 8},
]

def load_keys(url: str) -> list[str]:
    try:
        r = requests.get(url, timeout=15)
        return [l.strip() for l in r.text.splitlines() if l.strip().startswith('vless://')]
    except Exception:
        return []

def dedup(keys: list[str]) -> list[str]:
    seen, out = set(), []
    for k in keys:
        try:
            p   = urlparse(k)
            key = f"{p.hostname}:{p.port}"
            if key not in seen:
                seen.add(key); out.append(k)
        except Exception:
            out.append(k)
    return out

# =====================
# GITHUB SAVE
# =====================
def save_github(content: str):
    if not GITHUB_TOKEN:
        print("[SKIP] GH_TOKEN not set")
        return
    url     = f'https://api.github.com/repos/{GITHUB_REPO}/contents/{GITHUB_FILE}'
    headers = {'Authorization': f'token {GITHUB_TOKEN}',
               'Accept': 'application/vnd.github.v3+json'}
    sha = None
    r   = requests.get(url, headers=headers)
    if r.status_code == 200:
        sha = r.json().get('sha')
    data = {'message': 'Auto update REALITY+TCP',
            'content': base64.b64encode(content.encode()).decode(),
            'branch':  GITHUB_BRANCH}
    if sha:
        data['sha'] = sha
    r = requests.put(url, headers=headers, json=data)
    print('[OK] Saved to GitHub' if r.status_code in (200, 201)
          else f'[ERROR] GitHub {r.status_code}: {r.text[:200]}')

# =====================
# SORT
# =====================
COUNTRY_ORDER = {
    'Германия':1, 'Нидерланды':2, 'Франция':3,  'Италия':4,
    'Испания':5,  'Польша':6,     'Британия':7, 'США':8,
    'Канада':9,   'Австралия':10, 'Япония':11,  'Корея':12,
    'Россия':13,  'Anycast':999,
}

def key_sort_order(key_str: str) -> tuple[int, int]:
    try:
        fragment   = unquote(urlparse(key_str).fragment)
        wifi_first = 0 if 'WiFi' in fragment else 1
        for country, order in COUNTRY_ORDER.items():
            if country.lower() in fragment.lower():
                return wifi_first, order
        return wifi_first, 998
    except Exception:
        return 1, 998

# =====================
# MAIN
# =====================
def main():
    print("=" * 55)
    print("  SPECTER - REALITY + TCP + XRAY 204 CHECK")
    print("=" * 55)
    print("  Filter: security=reality, type=tcp, pbk=any")
    print("  fp & sni - any value accepted")
    print("=" * 55)

    xray_ok = install_xray()
    print(f"\n[XRAY] {'OK' if xray_ok else 'FAIL'}")
    if not xray_ok:
        return

    all_keys = []

    for src in IGARECK_SOURCES:
        name = src['url'].split('/')[-1]
        print(f"\n{'─'*55}")
        print(f"[{name}]")

        raw   = dedup(load_keys(src['url']))
        print(f"   loaded:          {len(raw)}")

        valid = [k for k in raw if is_valid_key(k)]
        print(f"   reality+tcp:     {len(valid)}/{len(raw)}")

        if not valid:
            print("   -> skip (no valid keys)")
            continue

        checked = check_all(valid, workers=10)
        print(f"   alive (204 OK):  {len(checked)}/{len(valid)}")

        top = checked[:src['top_n']]
        if top:
            print(f"   top score:       {chr(44).join(str(s) for _, s in top)}")

        for uri, _ in top:
            all_keys.append(rename_with_country(uri, src['lte']))

    print(f"\n{'='*55}")
    all_keys.sort(key=key_sort_order)

    wifi = sum(1 for k in all_keys if 'WiFi' in unquote(urlparse(k).fragment))
    lte  = sum(1 for k in all_keys if 'LTE'  in unquote(urlparse(k).fragment))
    print(f"TOTAL: {len(all_keys)} keys  ({wifi} WiFi / {lte} LTE)")

    if not all_keys:
        print("[WARN] No alive keys - GitHub not updated")
        return

    save_github(HEADER + '\n' + '\n'.join(all_keys))

if __name__ == '__main__':
    main()
