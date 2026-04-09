import requests
import os
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
    "🇩🇪": "Германия", "🇫🇷": "Франция",    "🇳🇱": "Нидерланды", "🇮🇹": "Италия",
    "🇪🇸": "Испания",  "🇵🇱": "Польша",      "🇧🇪": "Бельгия",    "🇦🇹": "Австрия",
    "🇨🇭": "Швейцария","🇸🇪": "Швеция",      "🇳🇴": "Норвегия",   "🇩🇰": "Дания",
    "🇫🇮": "Финляндия","🇬🇧": "Британия",    "🇺🇸": "США",        "🇨🇦": "Канада",
    "🇦🇺": "Австралия","🇯🇵": "Япония",       "🇰🇷": "Корея",      "🇸🇬": "Сингапур",
    "🇷🇺": "Россия",   "🇺🇦": "Украина",      "🇹🇷": "Турция",     "🇮🇱": "Израиль",
    "🇦🇪": "ОАЭ",      "🇮🇳": "Индия",        "🇧🇷": "Бразилия",   "🌐": "Anycast",
}

CODE_TO_FLAG = {
    "DE": "🇩🇪", "FR": "🇫🇷", "NL": "🇳🇱", "IT": "🇮🇹", "ES": "🇪🇸",
    "PL": "🇵🇱", "BE": "🇧🇪", "AT": "🇦🇹", "CH": "🇨🇭", "SE": "🇸🇪",
    "NO": "🇳🇴", "DK": "🇩🇰", "FI": "🇫🇮", "GB": "🇬🇧", "US": "🇺🇸",
    "CA": "🇨🇦", "AU": "🇦🇺", "JP": "🇯🇵", "KR": "🇰🇷", "SG": "🇸🇬",
    "RU": "🇷🇺", "UA": "🇺🇦", "TR": "🇹🇷", "IL": "🇮🇱", "AE": "🇦🇪",
    "IN": "🇮🇳", "BR": "🇧🇷",
}

# =====================
# XRAY BINARY
# =====================
XRAY_PATH = 'xray.exe' if os.name == 'nt' else '/tmp/xray'

def install_xray():
    if os.path.exists(XRAY_PATH):
        return True
    try:
        if os.name == 'nt':
            url = 'https://github.com/XTLS/Xray-core/releases/download/v1.8.6/Xray-windows-64.zip'
            r   = requests.get(url, timeout=60, stream=True)
            with open('xray.zip', 'wb') as f:
                for c in r.iter_content(8192): f.write(c)
            import zipfile
            with zipfile.ZipFile('xray.zip', 'r') as z: z.extractall('.')
            os.remove('xray.zip')
        else:
            r   = requests.get('https://api.github.com/repos/XTLS/Xray-core/releases/latest', timeout=15)
            ver = r.json()['tag_name']
            url = f'https://github.com/XTLS/Xray-core/releases/download/{ver}/Xray-linux-64.zip'
            r   = requests.get(url, timeout=60, stream=True)
            with open('/tmp/xray.zip', 'wb') as f:
                for c in r.iter_content(8192): f.write(c)
            import zipfile
            with zipfile.ZipFile('/tmp/xray.zip', 'r') as z: z.extract('xray', '/tmp/')
            os.chmod(XRAY_PATH, 0o755)
            os.remove('/tmp/xray.zip')
        return True
    except Exception as e:
        print(f"[XRAY install error] {e}")
        return False

# =====================
# PRE-FILTER CONSTANTS
# =====================

# CDN IP-префиксы — мгновенный skip
BAD_IP_PREFIXES = ('104.', '172.6', '172.7', '188.114.', '162.158.', '198.41.')

# Мусорные hostname паттерны
BAD_HOST_PATTERNS = ('workers.dev', 'pages.dev', 'cloudflare', 'fastly.net')

# Плохие CDN-провайдеры (убраны amazon/google — легитимные REALITY иногда на AWS/GCP)
BAD_ASN_ORGS = ('cloudflare', 'fastly', 'akamai', 'incapsula', 'imperva')

GENERATE_204_URLS = [
    'https://www.gstatic.com/generate_204',
    'https://www.google.com/generate_204',
    'https://cp.cloudflare.com/generate_204',
]

# =====================
# REALITY FILTER
# =====================
def is_reality(uri: str) -> bool:
    """Принимаем только VLESS + REALITY — лучший протокол для РФ."""
    try:
        p   = urlparse(uri)
        if p.scheme != 'vless':
            return False
        q   = parse_qs(p.query)
        sec = q.get('security', ['none'])[0].lower()
        pbk = q.get('pbk', [''])[0].strip()
        # Обязательно: security=reality и публичный ключ
        return sec == 'reality' and len(pbk) > 0
    except Exception:
        return False

# =====================
# QUICK PRE-CHECK
# =====================
def quick_filter(uri: str) -> tuple[bool, str]:
    """DNS + IP/host фильтр до запуска xray."""
    try:
        p    = urlparse(uri)
        host = (p.hostname or '').lower()

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
# VLESS PARSING
# =====================
def parse_vless(uri):
    try:
        p    = urlparse(uri)
        q    = parse_qs(p.query)
        h    = p.hostname
        pt   = p.port or 443
        u    = p.username
        sec  = q.get('security',    ['none'])[0]
        net  = q.get('type',        ['tcp'])[0]
        flow = q.get('flow',        [''])[0]
        sni  = q.get('sni',         [h])[0]
        fp   = q.get('fp',          ['chrome'])[0]
        pbk  = q.get('pbk',         [''])[0]
        sid  = q.get('sid',         [''])[0]
        path = q.get('path',        ['/'])[0]
        svc  = q.get('serviceName', [''])[0]

        stream = {'network': net}

        if sec == 'reality':
            stream['security'] = 'reality'
            stream['realitySettings'] = {
                'serverName': sni, 'fingerprint': fp,
                'publicKey': pbk,  'shortId': sid,
            }
        elif sec == 'tls':
            stream['security'] = 'tls'
            stream['tlsSettings'] = {'serverName': sni, 'allowInsecure': True}

        if net == 'ws':
            stream['wsSettings']   = {'path': path}
        elif net == 'grpc':
            stream['grpcSettings'] = {'serviceName': svc, 'multiMode': False}
        elif net == 'tcp':
            stream['tcpSettings']  = {}   # явный TCP для REALITY

        return {
            'protocol': 'vless',
            'settings': {
                'vnext': [{
                    'address': h,
                    'port':    pt,
                    'users':   [{'id': u, 'encryption': 'none', 'flow': flow}],
                }]
            },
            'streamSettings': stream,
        }
    except Exception:
        return None

def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

# =====================
# IP / ASN CHECKS
# =====================
def check_real_ip(proxies: dict, timeout: float = 5.0) -> tuple[bool, str]:
    """Два сервиса должны вернуть одинаковый IP — иначе CDN/балансер."""
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
    """CDN-ASN → reject."""
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
# PARALLEL 204 CHECK
# =====================
def check_204_parallel(proxies: dict, timeout: float = 4.0) -> list[float]:
    """
    Параллельный запрос к 3 generate_204 URL.
    Возвращает список успешных латентностей.
    Быстрее последовательного в ~3 раза.
    """
    latencies = []

    def fetch_one(url):
        try:
            t0 = time.time()
            r  = requests.get(url, proxies=proxies, timeout=timeout, allow_redirects=False)
            ms = round((time.time() - t0) * 1000, 1)
            return ms if r.status_code == 204 else None
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=3) as ex:
        futures = [ex.submit(fetch_one, url) for url in GENERATE_204_URLS]
        for f in as_completed(futures):
            result = f.result()
            if result is not None:
                latencies.append(result)

    return latencies

# =====================
# XRAY CHECK (CORE)
# =====================
def check_xray(uri: str, timeout: float = 8.0) -> float:
    """
    Полная проверка одного REALITY-ключа:
      1. quick_filter  — DNS + IP/host
      2. parse_vless   — валидность конфига
      3. xray запуск   — SOCKS5 локальный прокси
      4. 204 x3        — параллельно, нужно >= 2 успехов
      5. jitter <= 80ms
      6. real IP check — два сервиса совпадают
      7. ASN check     — не CDN

    Возвращает score (меньше = лучше) или 9999 при провале.
    REALITY даёт бонус -100 к score.
    """
    p    = urlparse(uri)
    host = p.hostname or ''

    # --- 1. quick filter ---
    ok, ip_or_err = quick_filter(uri)
    if not ok:
        print(f"      [SKIP] quick: {host} → {ip_or_err}")
        return 9999

    # --- 2. parse ---
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
    json.dump(cfg, tmp)
    tmp.close()

    proc = None
    try:
        # --- 3. запуск xray ---
        proc = subprocess.Popen(
            [XRAY_PATH, 'run', '-c', tmp.name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(1.5)   # даём xray подняться

        proxies = {
            'http':  f'socks5h://127.0.0.1:{port}',
            'https': f'socks5h://127.0.0.1:{port}',
        }

        # --- 4. параллельные 204 ---
        latencies = check_204_parallel(proxies, timeout=timeout)

        if len(latencies) < 2:
            print(f"      [SKIP] 204 fail ({len(latencies)}/3): {host}")
            return 9999

        avg    = statistics.mean(latencies)
        jitter = max(latencies) - min(latencies)
        print(f"      [204 OK] {host} avg={avg:.0f}ms jitter={jitter:.0f}ms")

        # --- 5. jitter ---
        if jitter > 80:
            print(f"      [SKIP] jitter {jitter:.0f}ms > 80ms")
            return 9999

        # --- 6. реальный IP ---
        ip_ok, ip_info = check_real_ip(proxies, timeout=5.0)
        if not ip_ok:
            print(f"      [SKIP] IP: {ip_info}")
            return 9999
        print(f"      [IP] {ip_info}")

        # --- 7. ASN ---
        asn_ok, org = check_asn(proxies, timeout=5.0)
        if not asn_ok:
            print(f"      [SKIP] ASN: {org}")
            return 9999
        print(f"      [ASN] {org}")

        # REALITY бонус -100 (всегда True здесь, но на всякий случай)
        q     = parse_qs(p.query)
        bonus = -100 if q.get('security', [''])[0].lower() == 'reality' else 0
        score = round(avg + jitter * 0.5 + bonus, 1)
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

# =====================
# PARALLEL CHECK
# =====================
def check_all(keys: list[str], workers: int = 10) -> list[tuple[str, float]]:
    """
    Параллельная проверка всех ключей.
    Возвращает [(uri, score)] отсортированный по score (меньше = лучше).
    """
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
                print(f"   [{done}/{len(keys)}] живых: {alive}", flush=True)

    results.sort(key=lambda x: x[1])
    return results

# =====================
# COUNTRY DETECTION
# =====================
def get_flag_and_country(fragment: str) -> tuple[str, str]:
    decoded     = unquote(fragment)
    flag_match  = re.search(r'([\U0001F1E0-\U0001F1FF]{2})', decoded)
    if flag_match:
        flag = flag_match.group(1)
        if flag in COUNTRY_RU:
            return flag, COUNTRY_RU[flag]
    return "🌐", "Anycast"

def extract_country(config: str) -> str:
    patterns = {
        'DE': ['de-','germany','berlin','frankfurt','🇩🇪'],
        'FR': ['fr-','france','paris','🇫🇷'],
        'NL': ['nl-','netherlands','amsterdam','rotterdam','🇳🇱'],
        'IT': ['it-','italy','rome','milan','🇮🇹'],
        'ES': ['es-','spain','madrid','🇪🇸'],
        'PL': ['pl-','poland','warsaw','🇵🇱'],
        'GB': ['gb-','uk','london','britain','england','🇬🇧'],
        'US': ['us-','usa','new york','nyc','🇺🇸'],
        'CA': ['ca-','canada','toronto','🇨🇦'],
        'JP': ['jp-','japan','tokyo','🇯🇵'],
        'RU': ['ru-','russia','moscow','spb','🇷🇺'],
    }
    config_lower = config.lower()
    for country, pats in patterns.items():
        if any(pat in config_lower for pat in pats):
            return country
    return 'OTHER'

def get_country_from_url(uri: str) -> tuple[str, str]:
    p             = urlparse(uri)
    flag, country = get_flag_and_country(p.fragment)
    if country != "Anycast":
        return flag, country

    code_to_info = {
        'DE': ('🇩🇪','Германия'),  'NL': ('🇳🇱','Нидерланды'),
        'FR': ('🇫🇷','Франция'),   'IT': ('🇮🇹','Италия'),
        'ES': ('🇪🇸','Испания'),   'PL': ('🇵🇱','Польша'),
        'GB': ('🇬🇧','Британия'),  'US': ('🇺🇸','США'),
        'CA': ('🇨🇦','Канада'),    'AU': ('🇦🇺','Австралия'),
        'JP': ('🇯🇵','Япония'),    'KR': ('🇰🇷','Корея'),
        'RU': ('🇷🇺','Россия'),
    }
    code = extract_country(uri)
    return code_to_info.get(code, ("🌐", "Anycast"))

# =====================
# RENAME
# =====================
def rename_with_country(uri: str, lte: bool) -> str:
    p             = urlparse(uri)
    flag, country = get_country_from_url(uri)
    tag           = "LTE" if lte else "WiFi"
    new_name      = f"{flag} {country} - {tag}"
    return urlunparse((p.scheme, p.netloc, p.path, p.params, p.query, quote(new_name)))

# =====================
# SOURCES
# =====================
IGARECK_SOURCES = [
    {'url': 'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS_mobile.txt',              'lte': False, 'top_n': 8},
    {'url': 'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt',                     'lte': False, 'top_n': 8},
    {'url': 'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile.txt', 'lte': True,  'top_n': 8},
    {'url': 'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile-2.txt','lte': True, 'top_n': 8},
    {'url': 'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/WHITE-CIDR-RU-checked.txt',               'lte': True,  'top_n': 8},
    {'url': 'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/WHITE-SNI-RU-all.txt',                    'lte': True,  'top_n': 8},
]

def load_keys(url: str) -> list[str]:
    try:
        r = requests.get(url, timeout=15)
        return [l.strip() for l in r.text.splitlines() if l.strip().startswith('vless://')]
    except Exception:
        return []

def dedup(keys: list[str]) -> list[str]:
    """Дедупликация по host:port."""
    seen, out = set(), []
    for k in keys:
        try:
            p   = urlparse(k)
            key = f"{p.hostname}:{p.port}"
            if key not in seen:
                seen.add(key)
                out.append(k)
        except Exception:
            out.append(k)
    return out

# =====================
# GITHUB SAVE
# =====================
def save_github(content: str):
    url     = f'https://api.github.com/repos/{GITHUB_REPO}/contents/{GITHUB_FILE}'
    headers = {
        'Authorization': f'token {GITHUB_TOKEN}',
        'Accept':        'application/vnd.github.v3+json',
    }
    sha = None
    r   = requests.get(url, headers=headers)
    if r.status_code == 200:
        sha = r.json().get('sha')

    data = {
        'message': 'Auto update REALITY keys',
        'content': base64.b64encode(content.encode()).decode(),
        'branch':  GITHUB_BRANCH,
    }
    if sha:
        data['sha'] = sha

    r = requests.put(url, headers=headers, json=data)
    if r.status_code in (200, 201):
        print('\n[OK] Сохранено в GitHub')
    else:
        print(f'\n[ERROR] GitHub: {r.status_code} — {r.text[:200]}')

# =====================
# COUNTRY SORT ORDER
# =====================
COUNTRY_ORDER = {
    'Германия':   1, 'Нидерланды': 2, 'Франция':   3,  'Италия':   4,
    'Испания':    5, 'Польша':     6, 'Британия':  7,  'США':      8,
    'Канада':     9, 'Австралия':  10, 'Япония':    11, 'Корея':    12,
    'Россия':     13, 'Anycast':   999,
}

def key_sort_order(key_str: str) -> tuple[int, int]:
    try:
        fragment = unquote(urlparse(key_str).fragment)
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
    print("  SPECTER — REALITY ONLY + XRAY 204 CHECK")
    print("=" * 55)

    if not GITHUB_TOKEN:
        print("[WARN] GH_TOKEN не задан — GitHub сохранение отключено")

    xray_ok = install_xray()
    print(f"[XRAY] {'OK' if xray_ok else 'FAIL — проверки отключены'}\n")

    if not xray_ok:
        return

    all_keys = []

    for src in IGARECK_SOURCES:
        name = src['url'].split('/')[-1]
        print(f"\n{'─'*50}")
        print(f"[{name}]")

        raw = dedup(load_keys(src['url']))
        print(f"   загружено:  {len(raw)}")

        reality_keys = [k for k in raw if is_reality(k)]
        print(f"   reality:    {len(reality_keys)}/{len(raw)}")

        if not reality_keys:
            print("   → пропуск (нет reality ключей)")
            continue

        checked = check_all(reality_keys, workers=10)
        print(f"   живых:      {len(checked)}/{len(reality_keys)}")

        top = checked[:src['top_n']]
        if top:
            scores_str = ', '.join(str(s) for _, s in top)
            print(f"   топ score:  {scores_str}")

        for uri, _ in top:
            all_keys.append(rename_with_country(uri, src['lte']))

    print(f"\n{'='*55}")

    # Сортировка: WiFi раньше LTE, внутри — по стране
    all_keys.sort(key=key_sort_order)

    wifi = sum(1 for k in all_keys if 'WiFi' in unquote(urlparse(k).fragment))
    lte  = sum(1 for k in all_keys if 'LTE'  in unquote(urlparse(k).fragment))
    print(f"ИТОГО: {len(all_keys)} ключей ({wifi} WiFi / {lte} LTE)")
    print("Все ключи — REALITY, проверены xray+204\n")

    if not all_keys:
        print("[WARN] Живых ключей нет — GitHub не обновляется")
        return

    content = HEADER + '\n' + '\n'.join(all_keys)
    save_github(content)

if __name__ == '__main__':
    main()
