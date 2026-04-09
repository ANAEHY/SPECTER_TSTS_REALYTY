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
GITHUB_TOKEN = os.getenv('GH_TOKEN')
GITHUB_REPO = 'ANAEHY/SPECTER'
GITHUB_FILE = 'keys.txt'
GITHUB_BRANCH = 'main'

HEADER = """#profile-title: base64:8J+RuyBTUEFDVEVSIFZQTg==
#profile-update-interval: 12"""

# =====================
# COUNTRY FLAGS
# =====================
COUNTRY_RU = {
    "🇩🇪": "Германия", "🇫🇷": "Франция", "🇳🇱": "Нидерланды", "🇮🇹": "Италия",
    "🇪🇸": "Испания", "🇵🇱": "Польша", "🇧🇪": "Бельгия", "🇦🇹": "Австрия",
    "🇨🇭": "Швейцария", "🇸🇪": "Швеция", "🇳🇴": "Норвегия", "🇩🇰": "Дания",
    "🇫🇮": "Финляндия", "🇬🇧": "Британия", "🇺🇸": "США", "🇨🇦": "Канада",
    "🇦🇺": "Австралия", "🇯🇵": "Япония", "🇰🇷": "Корея", "🇸🇬": "Сингапур",
    "🇷🇺": "Россия", "🇺🇦": "Украина", "🇹🇷": "Турция", "🇮🇱": "Израиль",
    "🇦🇪": "ОАЭ", "🇮🇳": "Индия", "🇧🇷": "Бразилия", "🌐": "Anycast",
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
# XRAY PATH
# =====================
XRAY_PATH = 'xray.exe' if os.name == 'nt' else '/tmp/xray'

def install_xray():
    if os.path.exists(XRAY_PATH):
        return True
    try:
        if os.name == 'nt':
            url = 'https://github.com/XTLS/Xray-core/releases/download/v1.8.6/Xray-windows-64.zip'
            r = requests.get(url, timeout=60, stream=True)
            with open('xray.zip', 'wb') as f:
                for c in r.iter_content(8192): f.write(c)
            import zipfile
            with zipfile.ZipFile('xray.zip', 'r') as z:
                z.extractall('.')
            os.remove('xray.zip')
        else:
            arch = 'linux-64'
            r = requests.get('https://api.github.com/repos/XTLS/Xray-core/releases/latest', timeout=15)
            ver = r.json()['tag_name']
            url = f'https://github.com/XTLS/Xray-core/releases/download/{ver}/Xray-{arch}.zip'
            r = requests.get(url, timeout=60, stream=True)
            with open('/tmp/xray.zip', 'wb') as f:
                for c in r.iter_content(8192): f.write(c)
            import zipfile
            with zipfile.ZipFile('/tmp/xray.zip', 'r') as z:
                z.extract('xray', '/tmp/')
            os.chmod(XRAY_PATH, 0o755)
            os.remove('/tmp/xray.zip')
        return True
    except:
        return False

# =====================
# COUNTRY DETECTION
# =====================
def get_flag_and_country(fragment: str):
    decoded = unquote(fragment)
    flag_match = re.search(r'([\U0001F1E0-\U0001F1FF]{2})', decoded)
    if flag_match:
        flag = flag_match.group(1)
        if flag in COUNTRY_RU:
            return flag, COUNTRY_RU[flag]
    return "🌐", "Anycast"

def extract_country(config):
    patterns = {
        'DE': ['de-', 'germany', 'de:', 'berlin', 'frankfurt', 'de/', '🇩🇪', 'germany', 'german'],
        'FR': ['fr-', 'france', 'fr:', 'paris', 'fr/', '🇫🇷', 'france', 'french'],
        'NL': ['nl-', 'netherlands', 'nl:', 'amsterdam', 'rotterdam', 'nl/', '🇳🇱', 'netherlands', 'dutch'],
        'IT': ['it-', 'italy', 'it:', 'rome', 'milan', 'it/', '🇮🇹', 'italy', 'italian'],
        'ES': ['es-', 'spain', 'es:', 'madrid', 'es/', '🇪🇸', 'spain', 'spanish'],
        'PL': ['pl-', 'poland', 'pl:', 'warsaw', 'pl/', '🇵🇱', 'poland', 'polish'],
        'GB': ['gb-', 'uk', 'gb:', 'london', 'uk/', '🇬🇧', 'britain', 'british', 'england'],
        'US': ['us-', 'usa', 'us:', 'new york', 'nyc', 'la/', '🇺🇸', 'usa', 'america'],
        'CA': ['ca-', 'canada', 'ca:', 'toronto', 'ca/', '🇨🇦', 'canada'],
        'JP': ['jp-', 'japan', 'jp:', 'tokyo', 'jp/', '🇯🇵', 'japan', 'japanese'],
        'RU': ['ru-', 'russia', 'ru:', 'moscow', 'spb', 'ru/', '🇷🇺', 'russia'],
    }
    config_lower = config.lower()
    for country, pats in patterns.items():
        if any(pat in config_lower for pat in pats):
            return country
    return 'OTHER'

def get_country_from_url(uri):
    p = urlparse(uri)
    flag, country = get_flag_and_country(p.fragment)
    if country != "Anycast":
        return flag, country
    country_code = extract_country(uri)
    country_map = {
        'DE': ('🇩🇪', 'Германия'), 'NL': ('🇳🇱', 'Нидерланды'),
        'FR': ('🇫🇷', 'Франция'),  'IT': ('🇮🇹', 'Италия'),
        'ES': ('🇪🇸', 'Испания'),  'PL': ('🇵🇱', 'Польша'),
        'GB': ('🇬🇧', 'Британия'), 'US': ('🇺🇸', 'США'),
        'CA': ('🇨🇦', 'Канада'),   'AU': ('🇦🇺', 'Австралия'),
        'JP': ('🇯🇵', 'Япония'),   'KR': ('🇰🇷', 'Корея'),
        'RU': ('🇷🇺', 'Россия'),
    }
    if country_code in country_map:
        return country_map[country_code]
    return "🌐", "Anycast"

# =====================
# REALITY PRE-FILTER
# =====================

# Cloudflare/CDN IP префиксы — мгновенный skip
BAD_IP_PREFIXES = ('104.', '172.6', '172.7', '188.114.', '162.158.', '198.41.')

# Мусорные hostname паттерны
BAD_HOST_PATTERNS = ('workers.dev', 'pages.dev', 'cloudflare', 'fastly.net')

# Плохие ASN провайдеры
BAD_ASN_ORGS = ('cloudflare', 'fastly', 'akamai', 'incapsula', 'imperva', 'amazon', 'google')

def is_reality(uri: str) -> bool:
    """
    Возвращает True только если ключ использует VLESS + REALITY.
    Это главный фильтр — берём только лучшее для РФ.
    """
    try:
        p = urlparse(uri)
        if p.scheme != 'vless':
            return False
        q = parse_qs(p.query)
        security = (q.get('security', ['none'])[0]).lower()
        return security == 'reality'
    except Exception:
        return False

def quick_filter(uri: str) -> tuple[bool, str]:
    """
    Быстрый фильтр до xray — hostname и IP.
    Возвращает (прошёл?, ip_или_причина_отказа).
    """
    try:
        p = urlparse(uri)
        host = (p.hostname or '').lower()

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
# PARSING
# =====================
def parse_vless(uri):
    try:
        p = urlparse(uri)
        q = parse_qs(p.query)
        h, pt = p.hostname, p.port or 443
        u = p.username
        sec  = q.get('security', ['none'])[0]
        net  = q.get('type', ['tcp'])[0]
        flow = q.get('flow', [''])[0]
        sni  = q.get('sni', [h])[0]
        fp   = q.get('fp', ['chrome'])[0]
        pbk  = q.get('pbk', [''])[0]
        sid  = q.get('sid', [''])[0]
        path = q.get('path', ['/'])[0]
        svc  = q.get('serviceName', [''])[0]

        stream = {'network': net}
        if sec == 'reality':
            stream['security'] = 'reality'
            stream['realitySettings'] = {
                'serverName': sni, 'fingerprint': fp,
                'publicKey': pbk, 'shortId': sid,
            }
        elif sec == 'tls':
            stream['security'] = 'tls'
            stream['tlsSettings'] = {'serverName': sni, 'allowInsecure': True}

        if net == 'ws':
            stream['wsSettings'] = {'path': path}
        elif net == 'grpc':
            stream['grpcSettings'] = {'serviceName': svc, 'multiMode': False}

        return {
            'protocol': 'vless',
            'settings': {'vnext': [{'address': h, 'port': pt,
                                     'users': [{'id': u, 'encryption': 'none', 'flow': flow}]}]},
            'streamSettings': stream,
        }
    except:
        return None

def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def check_tcp(host, port, timeout=2.0):
    try:
        t0 = time.time()
        with socket.create_connection((host, port), timeout=timeout):
            return round((time.time() - t0) * 1000, 1)
    except:
        return 9999

# =====================
# IP / ASN CHECKS (через прокси)
# =====================

def check_real_ip(proxies: dict, timeout: float = 5.0) -> tuple[bool, str]:
    """
    Проверяет реальный IP через 2 сервиса.
    Если не совпадают → CDN/балансер → False.
    """
    ips = []
    for url in ['https://api.ipify.org', 'https://ifconfig.me/ip']:
        try:
            r = requests.get(url, proxies=proxies, timeout=timeout)
            ip = r.text.strip()
            if ip and re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                ips.append(ip)
        except Exception:
            continue

    if len(ips) < 2:
        return True, ips[0] if ips else 'unknown'   # не смогли проверить — пропускаем

    if ips[0] != ips[1]:
        return False, f'balancer: {ips[0]} != {ips[1]}'

    for prefix in BAD_IP_PREFIXES:
        if ips[0].startswith(prefix):
            return False, f'CF IP: {ips[0]}'

    return True, ips[0]

def check_asn(proxies: dict, timeout: float = 5.0) -> tuple[bool, str]:
    """
    Проверяет ASN через ipinfo.io.
    Cloudflare/Fastly/Akamai → False.
    """
    try:
        r = requests.get('https://ipinfo.io/json', proxies=proxies, timeout=timeout)
        org = r.json().get('org', '').lower()
        for bad in BAD_ASN_ORGS:
            if bad in org:
                return False, org
        return True, org
    except Exception:
        return True, 'unknown'   # не смогли — не блокируем

# =====================
# CHECK XRAY (УЛУЧШЕННЫЙ)
# =====================

GENERATE_204_URLS = [
    'https://www.gstatic.com/generate_204',
    'https://www.google.com/generate_204',
    'https://cp.cloudflare.com/generate_204',
]

"""
ВРЕМЕННЫЙ ДЕБАГ — замени check_xray и check_all на эти версии
После того как найдём проблему — уберём дебаг
"""

def check_xray(uri, timeout=8.0):
    p = urlparse(uri)
    host = p.hostname or ''

    # Шаг 1: быстрый фильтр
    ok, ip_or_err = quick_filter(uri)
    if not ok:
        print(f"      [SKIP] quick_filter: {host} → {ip_or_err}")
        return 9999

    # Шаг 2: парсим outbound
    outbound = parse_vless(uri)
    if not outbound:
        print(f"      [SKIP] parse_vless fail: {host}")
        return 9999

    port = get_free_port()
    cfg = {
        'log': {'loglevel': 'none'},
        'inbounds': [{'port': port, 'listen': '127.0.0.1',
                      'protocol': 'socks',
                      'settings': {'auth': 'noauth'}}],
        'outbounds': [outbound, {'protocol': 'freedom'}],
    }

    f = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
    json.dump(cfg, f)
    f.close()

    proc = None
    try:
        proc = subprocess.Popen(
            [XRAY_PATH, 'run', '-c', f.name],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(2)

        proxies = {
            'http':  f'socks5h://127.0.0.1:{port}',
            'https': f'socks5h://127.0.0.1:{port}',
        }

        # Шаг 3: 3x generate_204
        latencies = []
        for url in GENERATE_204_URLS:
            try:
                t0 = time.time()
                r = requests.get(url, proxies=proxies, timeout=timeout, allow_redirects=False)
                ms = round((time.time() - t0) * 1000, 1)
                if r.status_code == 204:
                    latencies.append(ms)
            except Exception as e:
                pass

        if len(latencies) < 2:
            print(f"      [SKIP] 204 fail ({len(latencies)}/3): {host}")
            return 9999

        avg_latency = statistics.mean(latencies)
        jitter = max(latencies) - min(latencies)
        print(f"      [204 OK] {host} avg={avg_latency:.0f}ms jitter={jitter:.0f}ms")

        # Шаг 4: jitter
        if jitter > 150:
            print(f"      [SKIP] jitter too high: {jitter:.0f}ms")
            return 9999

        # Шаг 5: реальный IP
        ip_ok, ip_info = check_real_ip(proxies, timeout=5.0)
        if not ip_ok:
            print(f"      [SKIP] real IP fail: {ip_info}")
            return 9999
        print(f"      [IP OK] {ip_info}")

        # Шаг 6: ASN
        asn_ok, org = check_asn(proxies, timeout=5.0)
        if not asn_ok:
            print(f"      [SKIP] bad ASN: {org}")
            return 9999
        print(f"      [ASN OK] {org}")

        try:
            q = parse_qs(urlparse(uri).query)
            sec = q.get('security', ['none'])[0].lower()
            bonus = -100 if sec == 'reality' else 0
        except Exception:
            bonus = 0

        score = round(avg_latency + jitter * 0.5 + bonus, 1)
        print(f"      [✅ PASS] score={score}")
        return score

    except Exception as e:
        print(f"      [ERROR] {host}: {e}")
        return 9999
    finally:
        if proc:
            try: proc.kill(); proc.wait(timeout=2)
            except Exception: pass
        try: os.unlink(f.name)
        except Exception: pass


def check_all(keys):
    results = []

    def worker(uri):
        score = check_xray(uri, 8.0)
        if score < 9999:
            return uri, score
        return None, 9999

    # ДЕБАГ: только 5 потоков и первые 10 ключей чтобы читать лог
    test_keys = keys[:10]
    print(f"   [DEBUG] проверяем первые {len(test_keys)} ключей из {len(keys)}")

    with ThreadPoolExecutor(max_workers=5) as ex:
        futures = {ex.submit(worker, k): k for k in test_keys}
        done, alive = 0, 0
        for future in as_completed(futures):
            uri, score = future.result()
            done += 1
            if uri and score < 9999:
                results.append((uri, score))
                alive += 1

    print(f"   [DEBUG] результат: {alive}/{len(test_keys)} живых")
    results.sort(key=lambda x: x[1])
    return results

# =====================
# CHECK ALL (УЛУЧШЕННЫЙ)
# =====================

def check_all(keys):
    """
    Параллельная проверка.
    Возвращает [(uri, score)] отсортированный по score (меньше = лучше).
    """
    results = []

    def worker(uri):
        score = check_xray(uri, 8.0)
        if score < 9999:
            return uri, score
        return None, 9999

    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(worker, k): k for k in keys}
        done, alive = 0, 0
        for future in as_completed(futures):
            uri, score = future.result()
            done += 1
            if uri and score < 9999:
                results.append((uri, score))
                alive += 1
            if done % 20 == 0 or done == len(keys):
                print(f"   [{done}/{len(keys)}] alive: {alive}", flush=True)

    results.sort(key=lambda x: x[1])
    return results

# =====================
# SOURCES
# =====================
IGARECK_SOURCES = [
    {'url': 'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS_mobile.txt', 'lte': False, 'top_n': 8},
    {'url': 'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt', 'lte': False, 'top_n': 8},
    {'url': 'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile.txt', 'lte': True, 'top_n': 8},
    {'url': 'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile-2.txt', 'lte': True, 'top_n': 8},
    {'url': 'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/WHITE-CIDR-RU-checked.txt', 'lte': True, 'top_n': 8},
    {'url': 'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/WHITE-SNI-RU-all.txt', 'lte': True, 'top_n': 8},
]

def load_keys(url):
    try:
        r = requests.get(url, timeout=15)
        return [l.strip() for l in r.text.splitlines() if l.strip().startswith('vless://')]
    except:
        return []

def dedup(keys):
    seen, out = set(), []
    for k in keys:
        try:
            p = urlparse(k)
            key = f"{p.hostname}:{p.port}"
            if key not in seen:
                seen.add(key); out.append(k)
        except:
            out.append(k)
    return out

def rename_with_country(uri, lte):
    p = urlparse(uri)
    flag, country = get_country_from_url(uri)
    tag = "LTE" if lte else "WiFi"
    new_name = f"{flag} {country} - {tag}"
    return urlunparse((p.scheme, p.netloc, p.path, p.params, p.query, quote(new_name)))

def save_github(content):
    url = f'https://api.github.com/repos/{GITHUB_REPO}/contents/{GITHUB_FILE}'
    headers = {'Authorization': f'token {GITHUB_TOKEN}', 'Accept': 'application/vnd.github.v3+json'}
    sha = None
    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        sha = r.json().get('sha')
    data = {'message': 'Auto update', 'content': base64.b64encode(content.encode()).decode(), 'branch': GITHUB_BRANCH}
    if sha:
        data['sha'] = sha
    r = requests.put(url, headers=headers, json=data)
    if r.status_code in (200, 201):
        print('\n[OK] Saved to GitHub')
    else:
        print(f'\n[ERROR] {r.status_code}')

# =====================
# MAIN
# =====================
print("=" * 50)
print("SPECTER - REALITY ONLY + XRAY 204 CHECK")
print("=" * 50)

xray_ok = install_xray()
print(f"[XRAY] {'OK' if xray_ok else 'FAIL'}")

all_keys = []

for src in IGARECK_SOURCES:
    name = src['url'].split('/')[-1]
    print(f"\n[{name}]")

    raw = dedup(load_keys(src['url']))
    print(f"   loaded:  {len(raw)}")

    # ── ФИЛЬТР: только REALITY ───────────────────────────────────
    reality_keys = [k for k in raw if is_reality(k)]
    print(f"   reality: {len(reality_keys)}/{len(raw)}")

    if not reality_keys:
        print("   skip — no reality keys")
        continue

    # ── ПРОВЕРКА: xray + 204 ─────────────────────────────────────
    checked = check_all(reality_keys)
    print(f"   alive:   {len(checked)}/{len(reality_keys)}")

    top = checked[:src['top_n']]
    if top:
        print(f"   top scores: {', '.join(str(s) for _, s in top)}")

    for uri, _ in top:
        all_keys.append((rename_with_country(uri, src['lte']), uri))

# ── СОРТИРОВКА ───────────────────────────────────────────────────
COUNTRY_ORDER = {
    'Германия': 1, 'Нидерланды': 2, 'Франция': 3, 'Италия': 4, 'Испания': 5,
    'Польша': 6, 'Британия': 7, 'США': 8, 'Канада': 9, 'Австралия': 10,
    'Япония': 11, 'Корея': 12, 'Россия': 13, 'Anycast': 999,
}

def extract_country_order(key_str):
    try:
        fragment = unquote(urlparse(key_str).fragment)
        for country, order in COUNTRY_ORDER.items():
            if country.lower() in fragment.lower():
                return order
        return 998
    except:
        return 998

def get_key_type(key_str):
    return 0 if 'WiFi' in key_str else 1

all_keys.sort(key=lambda x: (get_key_type(x[0]), extract_country_order(x[0])))
all_keys = [k[0] for k in all_keys]

wifi  = sum(1 for k in all_keys if 'WiFi' in k)
lte   = sum(1 for k in all_keys if 'LTE'  in k)

print(f"\nTOTAL: {len(all_keys)} ({wifi} WiFi, {lte} LTE)")
print("Only REALITY keys — verified by xray+204")

content = HEADER + '\n' + '\n'.join(all_keys)
save_github(content)
