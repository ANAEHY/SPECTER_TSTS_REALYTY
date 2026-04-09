import requests
import os
import json
import time
import base64
import socket
import subprocess
import tempfile
import platform
import re
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
# XRAY - REAL 204 PROVERKA
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
        'DE': ('🇩🇪', 'Германия'),
        'NL': ('🇳🇱', 'Нидерланды'),
        'FR': ('🇫🇷', 'Франция'),
        'IT': ('🇮🇹', 'Италия'),
        'ES': ('🇪🇸', 'Испания'),
        'PL': ('🇵🇱', 'Польша'),
        'GB': ('🇬🇧', 'Британия'),
        'US': ('🇺🇸', 'США'),
        'CA': ('🇨🇦', 'Канада'),
        'AU': ('🇦🇺', 'Австралия'),
        'JP': ('🇯🇵', 'Япония'),
        'KR': ('🇰🇷', 'Корея'),
        'RU': ('🇷🇺', 'Россия'),
    }
    if country_code in country_map:
        return country_map[country_code]
    return "🌐", "Anycast"

# =====================
# PARSING
# =====================
def parse_vless(uri):
    try:
        p = urlparse(uri)
        q = parse_qs(p.query)
        h, pt = p.hostname, p.port or 443
        u = p.username
        sec = q.get('security', ['none'])[0]
        net = q.get('type', ['tcp'])[0]
        flow = q.get('flow', [''])[0]
        sni = q.get('sni', [h])[0]
        fp = q.get('fp', ['chrome'])[0]
        pbk = q.get('pbk', [''])[0]
        sid = q.get('sid', [''])[0]
        path = q.get('path', ['/'])[0]
        
        stream = {'network': net}
        if sec == 'reality':
            stream['security'] = 'reality'
            stream['realitySettings'] = {'serverName': sni, 'fingerprint': fp, 'publicKey': pbk, 'shortId': sid}
        elif sec == 'tls':
            stream['security'] = 'tls'
            stream['tlsSettings'] = {'serverName': sni, 'allowInsecure': True}
        if net == 'ws':
            stream['wsSettings'] = {'path': path}
        
        return {'protocol': 'vless', 'settings': {'vnext': [{'address': h, 'port': pt, 'users': [{'id': u, 'encryption': 'none', 'flow': flow}]}]}, 'streamSettings': stream}
    except:
        return None

def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

# =====================
# PROVERKA - XRAY + 204
# =====================
def check_xray(uri, timeout=8.0):
    outbound = parse_vless(uri)
    if not outbound:
        return 9999
    
    port = get_free_port()
    cfg = {
        'log': {'loglevel': 'none'},
        'inbounds': [{'port': port, 'listen': '127.0.0.1', 'protocol': 'socks', 'settings': {'auth': 'noauth'}}],
        'outbounds': [outbound, {'protocol': 'freedom'}],
    }
    
    f = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
    json.dump(cfg, f)
    f.close()
    
    proc = None
    try:
        proc = subprocess.Popen([XRAY_PATH, 'run', '-c', f.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)
        
        proxies = {'http': f'socks5h://127.0.0.1:{port}', 'https': f'socks5h://127.0.0.1:{port}'}
        
        for url in ['https://www.gstatic.com/generate_204', 'https://www.google.com/generate_204']:
            try:
                t0 = time.time()
                r = requests.get(url, proxies=proxies, timeout=timeout, allow_redirects=False)
                if r.status_code == 204:
                    return round((time.time() - t0) * 1000, 1)
            except:
                continue
        return 9999
    except:
        return 9999
    finally:
        if proc:
            try: proc.kill()
            except: pass
        try: os.unlink(f.name)
        except: pass

def check_tcp(host, port, timeout=2.0):
    try:
        t0 = time.time()
        with socket.create_connection((host, port), timeout=timeout):
            return round((time.time() - t0) * 1000, 1)
    except:
        return 9999

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

def check_all(keys):
    results = []
    
    def worker(uri):
        ms = check_xray(uri, 6.0)
        if ms < 9999:
            return uri, ms
        
        try:
            p = urlparse(uri)
            ms = check_tcp(p.hostname, p.port or 443, 2.0)
            if ms < 9999:
                return uri, ms + 50
        except:
            pass
        
        return None, 9999
    
    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(worker, k): k for k in keys}
        done, alive = 0, 0
        for f in as_completed(futures):
            uri, ms = f.result()
            done += 1
            if uri and ms < 9999:
                results.append((uri, ms))
                alive += 1
            if done % 20 == 0:
                print(f"   [{done}/{len(keys)}] alive: {alive}")
    
    results.sort(key=lambda x: x[1])
    return results

def rename_with_country(uri, lte):
    p = urlparse(uri)
    flag, country = get_country_from_url(uri)
    tag = f"LTE" if lte else "WiFi"
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
print("SPECTER - XRAY + 204 PROVERKA")
print("=" * 50)

xray_ok = install_xray()
print(f"[XRAY] {'OK' if xray_ok else 'NO - using TCP only'}")

all_keys = []
total = 0

for src in IGARECK_SOURCES:
    print(f"\n[{src['url'].split('/')[-1]}]")
    keys = dedup(load_keys(src['url']))
    print(f"   loaded: {len(keys)}")
    total += len(keys)
    if not keys:
        continue
    
    checked = check_all(keys)
    print(f"   alive: {len(checked)}/{len(keys)}")
    
    top = checked[:src['top_n']]
    if top:
        print(f"   top: {', '.join(f'{ms}ms' for _, ms in top)}")
    
    for uri, _ in top:
        all_keys.append((rename_with_country(uri, src['lte']), uri))

PRIORITY_COUNTRIES = ['DE', 'NL', 'FR', 'IT', 'ES', 'PL', 'GB']
COUNTRY_ORDER = {
    'Германия': 1, 'Нидерланды': 2, 'Франция': 3, 'Италия': 4, 'Испания': 5, 
    'Польша': 6, 'Британия': 7, 'США': 8, 'Канада': 9, 'Австралия': 10, 
    'Япония': 11, 'Корея': 12, 'Россия': 13, 'Anycast': 999
}

def get_key_type(key_str):
    return 0 if 'WiFi' in key_str else 1

def extract_country_order(key_str):
    try:
        from urllib.parse import unquote
        p = urlparse(key_str)
        fragment = unquote(p.fragment) if p.fragment else ''
        for country, order in COUNTRY_ORDER.items():
            if country.lower() in fragment.lower():
                return order
        return 998
    except:
        return 998

all_keys.sort(key=lambda x: (
    get_key_type(x[0]),
    extract_country_order(x[0])
))
all_keys = [k[0] for k in all_keys]

wifi = sum(1 for k in all_keys if 'WiFi' in k)
lte = sum(1 for k in all_keys if 'LTE' in k)

print(f"\nTOTAL: {len(all_keys)} ({wifi} WiFi, {lte} LTE)")

content = HEADER + '\n' + '\n'.join(all_keys)
save_github(content)
