#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import json
import base64
import hashlib
import secrets
import hmac
import re
import threading
import time
from datetime import datetime
from io import BytesIO
from urllib import request as urlrequest
from urllib.error import URLError, HTTPError
from urllib.parse import quote
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from config import (
    HOST, PORT, ADMIN_TOKEN, SERVER_LICENSE_SECRET, SUPABASE_URL, SUPABASE_SERVICE_KEY,
    SUPABASE_BACKUP_URL, SUPABASE_BACKUP_SERVICE_KEY, ALLOWED_ORIGINS,
    USERS_FILE, LICENSES_FILE, NOTICE_FILE, LOGS_FILE, BOT_FILE, BOT_ANDROID_FILE, GAMES_FILE, REVOKED_LICENSES_FILE, QUICK_LINKS_FILE
)

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": ALLOWED_ORIGINS or "*"}})
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["300 per minute"]
)

IV = b'dYQ9R99bkKLsLHad'
START_DATA_STATIC_UID = '5fc1680d30660d0037f390ba'
if not SERVER_LICENSE_SECRET:
    raise RuntimeError('SERVER_LICENSE_SECRET gerekli')

LICENSE_SECRET = hashlib.sha256(SERVER_LICENSE_SECRET.encode('utf-8')).digest()[:32]
pending_commands = []
client_pending_commands = []
last_bot_status = {
    "updated_at": "",
    "is_running": False,
    "is_paused": False,
    "is_playing": False,
    "pending_end_request": False,
    "current_game": None,
    "current_level": None,
    "status_text": "Hazır",
    "total_loaded_games": 0,
    "ready_games_count": 0,
    "total_played_games": 0,
    "total_power": 0,
    "instant_power": 0,
    "remaining_seconds": 0
}
REMOTE_STATE_KEYS = {
    str(USERS_FILE): 'users',
    str(LICENSES_FILE): 'licenses',
    str(NOTICE_FILE): 'notice',
    str(BOT_FILE): 'bot',
    str(BOT_ANDROID_FILE): 'bot_android',
    str(GAMES_FILE): 'games',
    str(REVOKED_LICENSES_FILE): 'revoked_licenses',
    str(QUICK_LINKS_FILE): 'quick_links',
}
MAX_LICENSE_KEY_LENGTH = 4096
MAX_NOTICE_TEXT_LENGTH = 4000
MAX_SCREENSHOT_B64_LENGTH = 8 * 1024 * 1024
MAX_JSON_FIELD_LENGTH = 2000
MAX_SESSIONS_PER_USER = 5
SCREENSHOT_MIN_INTERVAL_SECONDS = 5 * 60
SCREENSHOT_BLOCK_SECONDS = 60 * 60
SCREENSHOT_VIOLATION_WINDOW_SECONDS = 60 * 60
SCREENSHOT_VIOLATION_THRESHOLD = 3
screenshot_rate_state = {}


def _supabase_targets():
    targets = []
    seen = set()
    for name, url, key in (
        ('primary', SUPABASE_URL, SUPABASE_SERVICE_KEY),
        ('backup', SUPABASE_BACKUP_URL, SUPABASE_BACKUP_SERVICE_KEY),
    ):
        url = str(url or '').strip().rstrip('/')
        key = str(key or '').strip()
        if not url or not key or url in seen:
            continue
        seen.add(url)
        targets.append({'name': name, 'url': url, 'key': key})
    return targets


def _supabase_enabled():
    return bool(_supabase_targets())


def _supabase_headers(service_key):
    return {
        'apikey': service_key,
        'Authorization': f'Bearer {service_key}',
        'Content-Type': 'application/json'
    }


def _supabase_get_state(state_key, default):
    targets = _supabase_targets()
    if not targets:
        return default
    for target in targets:
        try:
            url = f"{target['url']}/rest/v1/app_state?key=eq.{quote(state_key)}&select=value"
            req = urlrequest.Request(url, headers=_supabase_headers(target['key']), method='GET')
            with urlrequest.urlopen(req, timeout=20) as resp:
                rows = json.loads(resp.read().decode('utf-8'))
            if rows and isinstance(rows, list):
                return rows[0].get('value', default)
        except Exception as e:
            log_event(f"Supabase load error [{target['name']}] ({state_key}): {e}")
    return default


def _supabase_set_state(state_key, value):
    targets = _supabase_targets()
    if not targets:
        return False
    body = json.dumps({
        'key': state_key,
        'value': value,
        'updated_at': datetime.now().isoformat()
    }).encode('utf-8')
    saved_any = False
    for target in targets:
        try:
            headers = _supabase_headers(target['key'])
            headers['Prefer'] = 'resolution=merge-duplicates'
            url = f"{target['url']}/rest/v1/app_state?on_conflict=key"
            req = urlrequest.Request(url, data=body, headers=headers, method='POST')
            with urlrequest.urlopen(req, timeout=20) as resp:
                resp.read()
            saved_any = True
        except Exception as e:
            log_event(f"Supabase save error [{target['name']}] ({state_key}): {e}")
    return saved_any


def load_json(path, default):
    state_key = REMOTE_STATE_KEYS.get(str(path))
    if state_key:
        remote = _supabase_get_state(state_key, None)
        if remote is not None:
            return remote
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except Exception:
        return default


def save_json(path, data):
    state_key = REMOTE_STATE_KEYS.get(str(path))
    if state_key:
        _supabase_set_state(state_key, data)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')


def log_event(event):
    with open(LOGS_FILE, 'a', encoding='utf-8') as f:
        f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {event}\n")


def get_request_ip(req=None):
    req = req or request
    forwarded = str(req.headers.get('X-Forwarded-For') or '').strip()
    if forwarded:
        return forwarded.split(',')[0].strip()
    return str(req.remote_addr or '').strip()


def log_admin_action(action, license_id=None, details=None):
    try:
        entry = {
            'time': datetime.now().isoformat(),
            'action': str(action or '').strip(),
            'license_id': str(license_id or '').strip(),
            'ip': get_request_ip(),
            'details': details or {}
        }
        log_event(f"ADMIN: {json.dumps(entry, ensure_ascii=False)}")
    except Exception as e:
        log_event(f'ADMIN LOG ERROR: {e}')


def verify_bot_files():
    for target_file, name in ((BOT_FILE, 'desktop'), (BOT_ANDROID_FILE, 'android')):
        try:
            content = target_file.read_text(encoding='utf-8', errors='ignore') if target_file.exists() else ''
            if not str(content or '').strip():
                log_event(f'WARNING: {name} bot dosyasi bos veya eksik')
                continue
            if 'function' not in content and '=>' not in content and '(function' not in content:
                log_event(f'WARNING: {name} bot dosyasi gecerli JS gibi gorunmuyor')
            checksum = hashlib.sha256(content.encode('utf-8')).hexdigest()[:16]
            log_event(f'Bot {name} checksum: {checksum}')
        except Exception as e:
            log_event(f'Bot verify error ({name}): {e}')


def check_license_anomaly(license_row, uid, fingerprint, client_ip):
    row = license_row or {}
    alerts = []
    last_uid = str(row.get('uid') or '').strip().lower()
    if last_uid and uid and last_uid != uid:
        alerts.append(f'UID degisikligi: {last_uid[:8]}... -> {uid[:8]}...')
    last_ip = str(row.get('last_ip') or '').strip()
    if last_ip and client_ip and last_ip != client_ip:
        try:
            if '.'.join(last_ip.split('.')[:3]) != '.'.join(client_ip.split('.')[:3]):
                alerts.append(f'IP degisikligi: {last_ip} -> {client_ip}')
        except Exception:
            alerts.append(f'IP degisikligi: {last_ip} -> {client_ip}')
    last_auth = str(row.get('last_auth_time') or '').strip()
    if last_auth:
        try:
            seconds_since = (datetime.now() - datetime.fromisoformat(last_auth)).total_seconds()
            if seconds_since < 60:
                alerts.append(f'Hizli auth: {seconds_since:.0f}s once')
        except Exception:
            pass
    if fingerprint and row.get('last_fingerprint') and str(row.get('last_fingerprint')) != str(fingerprint):
        alerts.append('Fingerprint degisikligi')
    for alert in alerts:
        log_event(f"ANOMALY [{row.get('license_id') or '-'}]: {alert}")
    if alerts:
        row['last_anomaly'] = datetime.now().isoformat()
        row['anomaly_count'] = int(row.get('anomaly_count') or 0) + len(alerts)
        row['status'] = 'suspicious'
        row['suspicious_reason'] = ' | '.join(alerts)[:500]
    row['last_ip'] = client_ip
    row['last_auth_time'] = datetime.now().isoformat()
    if fingerprint:
        row['last_fingerprint'] = str(fingerprint)
    return row


def check_admin(req):
    token = str(req.headers.get('X-Admin-Token') or '').strip()
    return bool(ADMIN_TOKEN) and bool(token) and hmac.compare_digest(token, ADMIN_TOKEN)


def secure_equals(left, right):
    left = str(left or '')
    right = str(right or '')
    return bool(left) and bool(right) and hmac.compare_digest(left, right)


def is_safe_text(value, max_len=MAX_JSON_FIELD_LENGTH):
    return len(str(value or '').strip()) <= max_len


def require_bot_identity(req, allow_query_uid=False):
    uid = str(req.headers.get('X-VIP-UID') or '').strip().lower()
    session_token = str(req.headers.get('X-VIP-Session-Token') or '').strip()
    client_id = str(req.headers.get('X-VIP-Client-ID') or '').strip()
    script_hash = str(req.headers.get('X-VIP-Script-Hash') or '').strip()
    if allow_query_uid and not uid:
        uid = str(req.args.get('uid') or '').strip().lower()
    if not uid or not session_token or not client_id:
        return None, (jsonify({'success': False, 'error': 'yetkisiz bot'}), 401)

    users = load_json(USERS_FILE, {})
    user = users.get(uid)
    if not user or not valid_session(user, session_token):
        return None, (jsonify({'success': False, 'error': 'yetkisiz bot'}), 401)

    licenses = load_json(LICENSES_FILE, {})
    license_id = user.get('license_id')
    row = licenses.get(license_id or '') or {}
    if not row or not row.get('active', True):
        return None, (jsonify({'success': False, 'error': 'off'}), 401)
    if str(row.get('uid') or '').strip().lower() != uid:
        return None, (jsonify({'success': False, 'error': 'script gecersiz'}), 401)
    if str(row.get('client_id') or '').strip() != client_id:
        return None, (jsonify({'success': False, 'error': 'script kimligi uyusmuyor'}), 401)
    expected_hash = str(row.get('script_hash') or '').strip()
    if expected_hash and script_hash and script_hash != expected_hash:
        return None, (jsonify({'success': False, 'error': 'script dogrulamasi basarisiz'}), 401)
    return {'uid': uid, 'user': user, 'license_id': license_id, 'license': row}, None


def normalize_lang(lang):
    lang = str(lang or 'tr').strip().lower()
    return {'tr': 'tr', 'en': 'en', 'pr': 'pr', 'pt': 'pr'}.get(lang, 'tr')


def client_hash_text(text: str):
    h = 0
    for ch in str(text):
        h = ((h << 5) - h) + ord(ch)
        h &= 0xffffffff
    signed = h if h < 0x80000000 else h - 0x100000000
    return 'h' + format(abs(signed), 'x')


def decrypt_license_for_server(token: str):
    try:
        raw = base64.urlsafe_b64decode(str(token).encode('utf-8'))
        cipher = AES.new(LICENSE_SECRET, AES.MODE_CBC, IV)
        plaintext = unpad(cipher.decrypt(raw), AES.block_size).decode('utf-8')
        return json.loads(plaintext)
    except Exception:
        return None


def load_revoked_licenses():
    data = load_json(REVOKED_LICENSES_FILE, [])
    return data if isinstance(data, list) else []


def save_revoked_licenses(items):
    save_json(REVOKED_LICENSES_FILE, items if isinstance(items, list) else [])


def is_revoked_license(license_id='', encrypted_license='', client_id='', script_hash=''):
    license_id = str(license_id or '').strip()
    encrypted_license = str(encrypted_license or '').strip()
    client_id = str(client_id or '').strip()
    script_hash = str(script_hash or '').strip()
    for item in load_revoked_licenses():
        if license_id and str(item.get('license_id') or '').strip() == license_id:
            return True
        if encrypted_license and str(item.get('encrypted_license') or '').strip() == encrypted_license:
            return True
        if client_id and str(item.get('client_id') or '').strip() == client_id:
            return True
        if script_hash and str(item.get('script_hash') or '').strip() == script_hash:
            return True
    return False


def load_quick_links():
    data = load_json(QUICK_LINKS_FILE, {'active': False, 'telegram': '', 'youtube': '', 'login': ''})
    if not isinstance(data, dict):
        data = {}
    return {
        'active': bool(data.get('active', False)),
        'telegram': str(data.get('telegram') or '').strip(),
        'youtube': str(data.get('youtube') or '').strip(),
        'login': str(data.get('login') or '').strip(),
        'normal': str(data.get('normal') or '').strip(),
    }


def save_quick_links(data):
    save_json(QUICK_LINKS_FILE, {
        'active': bool((data or {}).get('active', False)),
        'telegram': str((data or {}).get('telegram') or '').strip(),
        'youtube': str((data or {}).get('youtube') or '').strip(),
        'login': str((data or {}).get('login') or '').strip(),
        'normal': str((data or {}).get('normal') or '').strip(),
    })


def patch_bot_content(content: str):
    server_url = request.host_url.rstrip('/')
    content = re.sub(r"const\s+PY_URL\s*=\s*['\"]http://127\.0\.0\.1:\d+['\"]\s*;", f"const PY_URL = '{server_url}';", content)
    content = content.replace('__SERVER_URL__', server_url)
    content = content.replace('http://127.0.0.1:5003', server_url)
    content = content.replace('http://127.0.0.1:5005', server_url)
    return content


def get_variant_file(is_android=False):
    return BOT_ANDROID_FILE if is_android else BOT_FILE


def load_variant_bot_content(is_android=False):
    target_file = get_variant_file(is_android)
    fallback_file = BOT_FILE
    bot_content = load_json(target_file, '') if _supabase_enabled() else target_file.read_text(encoding='utf-8', errors='ignore')
    if isinstance(bot_content, dict):
        bot_content = ''
    bot_content = str(bot_content or '')
    if not bot_content.strip() and is_android:
        fallback_content = load_json(fallback_file, '') if _supabase_enabled() else fallback_file.read_text(encoding='utf-8', errors='ignore')
        if isinstance(fallback_content, dict):
            fallback_content = ''
        bot_content = str(fallback_content or '')
    return bot_content


def save_variant_bot_content(content: str, is_android=False):
    target_file = get_variant_file(is_android)
    content = re.sub(r"const\s+PY_URL\s*=\s*['\"]http://127\.0\.0\.1:\d+['\"]\s*;", "const PY_URL = '__SERVER_URL__';", content)
    content = content.replace('http://127.0.0.1:5003', '__SERVER_URL__')
    content = content.replace('http://127.0.0.1:5005', '__SERVER_URL__')
    save_json(target_file, content)
    target_file.write_text(content, encoding='utf-8')


ANDROID_UI_PATCH = r'''
(function(){
    try {
        if (window.__VIP_ANDROID_UI_PATCHED__) return;
        window.__VIP_ANDROID_UI_PATCHED__ = true;
        const style = document.createElement('style');
        style.textContent = `
            .rc-float-window{max-width:96vw !important;min-width:0 !important;touch-action:none !important;}
            #bot-main-window{width:min(96vw,460px) !important;right:2vw !important;left:auto !important;top:10px !important;}
            #games-window,#settings-window,#selected-games-window,#miner-window,#history-window,#game-status-window,#level-window,#play-confirm-window{width:min(96vw,var(--vip-mobile-w,720px)) !important;max-width:96vw !important;left:2vw !important;right:auto !important;}
            .rc-float-header{padding:14px 16px !important;touch-action:none !important;}
            .rc-btn,.btn-close-window,.rc-modern-btn{min-height:42px !important;font-size:12px !important;}
            .rc-hamster-btn{width:78px !important;height:78px !important;bottom:16px !important;right:16px !important;}
            .rc-log{font-size:11px !important;}
            @media (max-width: 900px){
                #bot-main-window{width:96vw !important;}
                #main-content{max-height:74vh !important;padding:12px !important;}
                .rc-action-grid,.rc-action-grid.secondary{grid-template-columns:1fr !important;}
                #games-list-content{grid-template-columns:1fr !important;}
                .level-stats{grid-template-columns:1fr !important;}
            }
        `;
        document.head.appendChild(style);

        let state = null;
        const getWin = (el) => el && (el.classList?.contains('rc-float-window') ? el : el.closest('.rc-float-window'));

        document.addEventListener('pointerdown', (e) => {
            if (e.pointerType !== 'touch' && e.pointerType !== 'pen') return;
            const header = e.target.closest('.rc-float-header');
            const win = getWin(header);
            if (!header || !win) return;
            if (e.target.closest('button,input,select,textarea,label,a')) return;
            const rect = win.getBoundingClientRect();
            state = { id: e.pointerId, win, startX: e.clientX, startY: e.clientY, offsetX: e.clientX - rect.left, offsetY: e.clientY - rect.top, moved: false };
            win.style.left = rect.left + 'px';
            win.style.top = rect.top + 'px';
            win.style.right = 'auto';
            win.style.bottom = 'auto';
            win.classList.add('dragging');
        }, true);

        document.addEventListener('pointermove', (e) => {
            if (!state || e.pointerId !== state.id) return;
            const maxLeft = Math.max(0, window.innerWidth - state.win.offsetWidth);
            const maxTop = Math.max(0, window.innerHeight - state.win.offsetHeight);
            const left = Math.max(0, Math.min(maxLeft, e.clientX - state.offsetX));
            const top = Math.max(0, Math.min(maxTop, e.clientY - state.offsetY));
            state.win.style.left = left + 'px';
            state.win.style.top = top + 'px';
            if (Math.abs(e.clientX - state.startX) > 4 || Math.abs(e.clientY - state.startY) > 4) state.moved = true;
        }, true);

        document.addEventListener('pointerup', (e) => {
            if (!state || e.pointerId !== state.id) return;
            const moved = state.moved;
            state.win.classList.remove('dragging');
            const targetWin = state.win;
            state = null;
            if (moved) {
                e.preventDefault();
                e.stopPropagation();
                targetWin.__vipTouchDraggedAt = Date.now();
            }
        }, true);

        document.addEventListener('click', (e) => {
            const win = getWin(e.target);
            if (win && win.__vipTouchDraggedAt && Date.now() - win.__vipTouchDraggedAt < 350) {
                e.preventDefault();
                e.stopPropagation();
            }
        }, true);
    } catch (e) {}
})();
'''


def apply_android_bot_patch(content: str):
    content = str(content or '')
    if not content.strip() or 'window.__VIP_ANDROID_UI_PATCHED__' in content:
        return content
    marker = '\n})();'
    if marker in content:
        return content.rsplit(marker, 1)[0] + '\n' + ANDROID_UI_PATCH + marker
    return content + '\n' + ANDROID_UI_PATCH


def generate_key(user_id):
    user_id = str(user_id).strip()
    t = list(user_id)
    a = [int(c) for c in t if c.isdigit()]
    s = sum(a)
    n = sorted(a)
    slice_t = t[:len(n)]
    i = [str(x) for x in n] + slice_t + [str(s)]
    oe_result = ''.join(i)
    md5_hash = hashlib.md5(oe_result.encode()).hexdigest()
    return (md5_hash + md5_hash).encode()[:32]


def encrypt_with_uid(data, uid):
    key = generate_key(uid)
    plaintext = json.dumps(data) if isinstance(data, dict) else str(data)
    padded = pad(plaintext.encode('utf-8'), AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, IV)
    encrypted = cipher.encrypt(padded)
    return base64.b64encode(encrypted).decode('utf-8')


def decrypt_with_uid(encrypted_text, uid):
    try:
        key = generate_key(uid)
        raw = base64.b64decode(str(encrypted_text).strip())
        cipher = AES.new(key, AES.MODE_CBC, IV)
        decrypted = cipher.decrypt(raw)
        plaintext = unpad(decrypted, AES.block_size).decode('utf-8')
        try:
            return json.loads(plaintext)
        except Exception:
            return plaintext
    except Exception:
        return None


def normalize_game_start_data(value):
    if isinstance(value, (dict, list)):
        return value
    text = str(value or '').strip()
    if not text:
        return ''
    if text.startswith('{') or text.startswith('['):
        try:
            return json.loads(text)
        except Exception:
            return text
    decoded = decrypt_with_uid(text, START_DATA_STATIC_UID)
    if decoded is None:
        return text
    if isinstance(decoded, str):
        dtext = decoded.strip()
        if dtext.startswith('{') or dtext.startswith('['):
            try:
                return json.loads(dtext)
            except Exception:
                return dtext
        return dtext
    return decoded


def normalize_games_map(games):
    if not isinstance(games, dict):
        return {}
    normalized = {}
    for key, game in games.items():
        row = dict(game or {})
        row['start_data'] = normalize_game_start_data(row.get('start_data'))
        normalized[key] = row
    return normalized


def encrypt_bot_for_uid(bot_code: str, uid: str):
    key_bytes = (uid.encode('utf-8') * 128)
    src = bot_code.encode('utf-8')
    xored = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(src))
    return base64.b64encode(xored).decode('utf-8')


def send_telegram_api(token, method, payload):
    token = str(token or '').strip()
    if not token:
        return False, {'error': 'telegram token bos'}
    try:
        url = f"https://api.telegram.org/bot{token}/{method}"
        body = json.dumps(payload).encode('utf-8')
        req = urlrequest.Request(url, data=body, headers={'Content-Type': 'application/json'}, method='POST')
        with urlrequest.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode('utf-8'))
        return bool(data.get('ok')), data
    except (HTTPError, URLError) as e:
        return False, {'error': str(e)}
    except Exception as e:
        return False, {'error': str(e)}


def send_telegram_photo(token, chat_id, photo_bytes, caption=''):
    token = str(token or '').strip()
    chat_id = str(chat_id or '').strip()
    if not token or not chat_id:
        return False, {'error': 'telegram bilgisi eksik'}
    boundary = '----RollerVipBoundary' + secrets.token_hex(8)
    body = BytesIO()

    def _write_field(name, value):
        body.write(f'--{boundary}\r\n'.encode('utf-8'))
        body.write(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode('utf-8'))
        body.write(str(value).encode('utf-8'))
        body.write(b'\r\n')

    _write_field('chat_id', chat_id)
    if caption:
        _write_field('caption', caption)
    body.write(f'--{boundary}\r\n'.encode('utf-8'))
    body.write(b'Content-Disposition: form-data; name="photo"; filename="roller_vip.png"\r\n')
    body.write(b'Content-Type: image/png\r\n\r\n')
    body.write(photo_bytes)
    body.write(b'\r\n')
    body.write(f'--{boundary}--\r\n'.encode('utf-8'))

    try:
        req = urlrequest.Request(
            f'https://api.telegram.org/bot{token}/sendPhoto',
            data=body.getvalue(),
            headers={'Content-Type': f'multipart/form-data; boundary={boundary}'},
            method='POST'
        )
        with urlrequest.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode('utf-8'))
        return bool(data.get('ok')), data
    except (HTTPError, URLError) as e:
        return False, {'error': str(e)}
    except Exception as e:
        return False, {'error': str(e)}


def format_retry_time(epoch_seconds):
    try:
        return datetime.fromtimestamp(float(epoch_seconds)).strftime('%d.%m.%Y %H:%M:%S')
    except Exception:
        return '-'


def screenshot_caption_by_lang(lang='tr'):
    lang = normalize_lang(lang)
    if lang == 'en':
        return 'Roller VIP screenshot\nNOTE: You can request 1 screenshot every 5 minutes.'
    if lang == 'pr':
        return 'Captura de tela Roller VIP\nNOTA: Voce pode solicitar 1 captura a cada 5 minutos.'
    return 'Roller VIP ekran goruntusu\nNOT: 5 dakikada 1 isteyebilirsin.'


def screenshot_block_message_by_lang(lang='tr', retry_text='-'):
    lang = normalize_lang(lang)
    if lang == 'en':
        return f'⛔ Too many screenshot requests detected.\n\nTimeout: 1 hour\nAvailable again: {retry_text}'
    if lang == 'pr':
        return f'⛔ Muitas solicitacoes de captura foram detectadas.\n\nTempo de espera: 1 hora\nLiberado novamente: {retry_text}'
    return f'⛔ Cok fazla ekran alma istegi algilandi.\n\nZaman asimi: 1 saat\nTekrar acilma: {retry_text}'


def check_screenshot_rate_limit(license_id=''):
    now = time.time()
    key = str(license_id or '-').strip() or '-'
    state = screenshot_rate_state.setdefault(key, {
        'cooldown_until': 0.0,
        'blocked_until': 0.0,
        'violations': []
    })
    state['violations'] = [ts for ts in (state.get('violations') or []) if (now - float(ts)) <= SCREENSHOT_VIOLATION_WINDOW_SECONDS]

    blocked_until = float(state.get('blocked_until') or 0.0)
    if blocked_until > now:
        return False, 'blocked', blocked_until

    cooldown_until = float(state.get('cooldown_until') or 0.0)
    if cooldown_until > now:
        state['violations'].append(now)
        if len(state['violations']) >= SCREENSHOT_VIOLATION_THRESHOLD:
            state['blocked_until'] = now + SCREENSHOT_BLOCK_SECONDS
            state['cooldown_until'] = state['blocked_until']
            return False, 'blocked_new', state['blocked_until']
        return False, 'cooldown', cooldown_until

    state['cooldown_until'] = now + SCREENSHOT_MIN_INTERVAL_SECONDS
    return True, 'ok', state['cooldown_until']


def build_license_telegram_menu(_license_id=None):
    return {
        'keyboard': [
            ['🎮 Bot Durumu'],
            ['▶️ Başlat', '⏹️ Durdur'],
            ['📸 Ekran Al', '🧹 İstatistik Sıfırla']
        ],
        'resize_keyboard': True,
        'one_time_keyboard': False,
        'is_persistent': True
    }


def build_license_menu_text(action=None, extra=None):
    action = str(action or '').strip().lower()
    if action == 'start':
        return '▶️ Baslat komutu gonderildi.'
    if action == 'stop':
        return '⏹️ Durdur komutu gonderildi.'
    if action == 'refresh':
        return '🔄 Sayfa yenile komutu gonderildi.'
    if action == 'screenshot':
        return '📸 Ekran alma komutu gonderildi.'
    if action == 'reset_stats':
        return '🧹 Istatistik sifirlama komutu gonderildi.'
    return '🎮 Roller VIP kontrol menusu\n\nAlt menuden islem sec.'


def format_remaining_time(seconds):
    try:
        seconds = int(seconds or 0)
    except Exception:
        seconds = 0
    if seconds < 0:
        seconds = 0
    mins, secs = divmod(seconds, 60)
    hours, mins = divmod(mins, 60)
    if hours:
        return f'{hours}s {mins:02d}dk {secs:02d}sn'
    return f'{mins}dk {secs:02d}sn'


def is_license_online(row, now=None):
    now = now or datetime.now()
    hb = str((row or {}).get('last_heartbeat') or '').strip()
    if not hb:
        return False
    try:
        return (now - datetime.fromisoformat(hb)).total_seconds() <= 90
    except Exception:
        return False


def get_license_status_text(_license_row=None):
    st = last_bot_status or {}
    return (
        f"📊 Durum Bildirimi\n\n"
        f"Hazir oyun sayisi: {st.get('ready_games_count', 0)}\n"
        f"Anlik toplam oynanan: {st.get('total_played_games', 0)}\n"
        f"Su an oynanan oyun: {st.get('current_game') or '-'}\n"
        f"Kalan sure: {format_remaining_time(st.get('remaining_seconds', 0))}\n"
        f"Anlik power: {st.get('instant_power', 0)}\n"
        f"Toplam power: {st.get('total_power', 0)}"
    )


def _send_license_reply(license_row, text, with_menu=False):
    payload = {
        'chat_id': str(license_row.get('telegram_chat_id') or '').strip(),
        'text': text
    }
    if with_menu:
        payload['reply_markup'] = build_license_telegram_menu(license_row.get('license_id'))
    return send_telegram_api(license_row.get('telegram_token'), 'sendMessage', payload)


def send_license_telegram_menu(license_row):
    token = str(license_row.get('telegram_token') or '').strip()
    chat_id = str(license_row.get('telegram_chat_id') or '').strip()
    if not token or not chat_id:
        return False, {'error': 'telegram bilgisi eksik'}
    return send_telegram_api(token, 'sendMessage', {
        'chat_id': chat_id,
        'text': build_license_menu_text(),
        'reply_markup': build_license_telegram_menu(license_row.get('license_id'))
    })


def queue_bot_command(command):
    pending_commands.append({'command': command, 'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'source': 'telegram'})


def queue_client_command(command):
    client_pending_commands.append({'command': command, 'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'source': 'telegram'})


def process_telegram_action(license_row, action):
    action = str(action or '').strip().lower()
    if action in {'menu', 'open_menu'}:
        return _send_license_reply(license_row, build_license_menu_text(), True)
    if action in {'status', 'bot_status'}:
        return _send_license_reply(license_row, get_license_status_text(license_row), True)
    if action == 'start':
        queue_bot_command('start')
        return _send_license_reply(license_row, build_license_menu_text('start'), True)
    if action == 'stop':
        queue_bot_command('stop')
        return _send_license_reply(license_row, build_license_menu_text('stop'), True)
    if action == 'refresh':
        queue_client_command('refresh_page')
        return _send_license_reply(license_row, build_license_menu_text('refresh'), True)
    if action == 'screenshot':
        queue_client_command('send_screenshot')
        return _send_license_reply(license_row, build_license_menu_text('screenshot'), True)
    if action == 'reset_stats':
        queue_bot_command('reset_stats')
        return _send_license_reply(license_row, build_license_menu_text('reset_stats'), True)
    return _send_license_reply(license_row, build_license_menu_text(), True)


def poll_all_telegram_bots():
    tg_offsets = {}
    while True:
        try:
            licenses = load_json(LICENSES_FILE, {})
            changed = False
            for lid, row in licenses.items():
                token = str(row.get('telegram_token') or '').strip()
                chat_id = str(row.get('telegram_chat_id') or '').strip()
                if not token or not chat_id:
                    continue
                key = token[-24:]
                offset = int(tg_offsets.get(key, 0) or 0)
                ok, data = send_telegram_api(token, 'getUpdates', {'offset': offset, 'timeout': 0, 'allowed_updates': ['message']})
                if not ok:
                    continue
                for upd in data.get('result', []):
                    update_id = int(upd.get('update_id', 0) or 0)
                    if update_id >= offset:
                        tg_offsets[key] = update_id + 1
                        changed = True
                    msg = upd.get('message') or {}
                    incoming_chat = str(((msg.get('chat') or {}).get('id')) or '').strip()
                    if incoming_chat != chat_id:
                        continue
                    text = str(msg.get('text') or '').strip().lower()
                    if text in {'/start', '/menu', 'menu'}:
                        process_telegram_action(row, 'menu')
                    elif text in {'/durum', 'durum', 'status', '/status', '🎮 bot durumu'}:
                        process_telegram_action(row, 'status')
                    elif text in {'▶️ başlat', '▶️ baslat'}:
                        process_telegram_action(row, 'start')
                    elif text in {'⏹️ durdur'}:
                        process_telegram_action(row, 'stop')
                    elif text in {'📸 ekran al'}:
                        process_telegram_action(row, 'screenshot')
                    elif text in {'🧹 i̇statistik sıfırla', '🧹 istatistik sıfırla', '🧹 istatistik sifirla'}:
                        process_telegram_action(row, 'reset_stats')
            if changed:
                log_event('Telegram polling aktif')
        except Exception as e:
            log_event(f'Telegram polling error: {e}')
        threading.Event().wait(5)


def _to_int(value, default=0):
    try:
        return int(value)
    except Exception:
        try:
            return int(float(value))
        except Exception:
            return default


def normalize_percent_value(raw_value=0):
    return float(raw_value or 0) / 100.0


def calculate_miner_base_effective_power(miner=None):
    miner = miner or {}
    power = float(miner.get('power') or 0)
    miner_bonus_percent = normalize_percent_value(miner.get('bonus_percent') or 0)
    return int(round(power * (1 + (miner_bonus_percent / 100.0))))


def calculate_rack_boosted_power(miner_or_power=0, rack_bonus=0):
    if isinstance(miner_or_power, dict):
        base_effective_power = calculate_miner_base_effective_power(miner_or_power)
    else:
        base_effective_power = float(miner_or_power or 0)
    rack_bonus_percent = normalize_percent_value(rack_bonus or 0)
    return int(round(base_effective_power * (1 + (rack_bonus_percent / 100.0))))


def expand_inventory_miner_items(items=None):
    expanded = []
    for item in (items or []):
        quantity = max(0, _to_int(item.get('quantity') or 0))
        for idx in range(quantity):
            row = dict(item or {})
            row['_id'] = f"inventory-{item.get('miner_id') or 'miner'}-{idx}"
            row['source'] = 'inventory'
            row['placement'] = None
            expanded.append(row)
    return expanded


def expand_inventory_rack_items(items=None):
    expanded = []
    for item in (items or []):
        quantity = max(0, _to_int(item.get('quantity') or 0))
        for idx in range(quantity):
            row = dict(item or {})
            row['_id'] = f"inventory-rack-{item.get('rack_id') or 'rack'}-{idx}"
            row['source'] = 'inventory'
            row['placement'] = None
            row['rack_info'] = row.get('rack_info') or {'width': 2, 'height': (_to_int(row.get('cells') or 0) // 2) or 3}
            row['bonus'] = _to_int(row.get('bonus') or 0)
            expanded.append(row)
    return expanded


def ensure_room_data_augmented(room_data):
    room_data = dict(room_data or {})
    room_data['inventoryItems'] = room_data.get('inventoryItems') or []
    room_data['rackInventoryItems'] = room_data.get('rackInventoryItems') or []
    room_data['miners'] = room_data.get('miners') or []
    room_data['racks'] = room_data.get('racks') or []
    room_data['minersAll'] = room_data.get('minersAll') or ([dict(m, source='room') for m in room_data['miners']] + expand_inventory_miner_items(room_data['inventoryItems']))
    room_data['racksAll'] = room_data.get('racksAll') or ([dict(r, source='room') for r in room_data['racks']] + expand_inventory_rack_items(room_data['rackInventoryItems']))
    return room_data


def get_room_rack_grid_info(room_data):
    racks = room_data.get('racks') or []
    first_rack = racks[0] if racks else {}
    rooms_available = room_data.get('rooms_available') or []
    first_room = rooms_available[0] if rooms_available else {}
    user_room_id = (((first_rack.get('placement') or {}).get('user_room_id')) or first_room.get('_id') or '')
    room_level = _to_int(((first_rack.get('placement') or {}).get('room_level')) or ((first_room.get('room_info') or {}).get('level')) or 0)
    room_levels = ((room_data.get('appearance') or {}).get('room_levels_config') or [])
    room_config = next((cfg for cfg in room_levels if _to_int(cfg.get('level') or 0) == room_level), None) or (room_levels[0] if room_levels else None) or first_room.get('room_info') or {}
    slot_cols = max(1, _to_int(room_config.get('cols') or 8) // 2)
    slot_rows = max(1, _to_int(room_config.get('rows') or 3))
    return {'userRoomId': user_room_id, 'roomLevel': room_level, 'slotCols': slot_cols, 'slotRows': slot_rows, 'totalSlots': slot_cols * slot_rows}


def get_rack_candidate_value(rack=None):
    rack = rack or {}
    height = _to_int(((rack.get('rack_info') or {}).get('height')) or 0)
    bonus_percent = normalize_percent_value(rack.get('bonus') or 0)
    return height * (1 + (bonus_percent / 100.0))


def rack_cmp_tuple(rack=None):
    rack = rack or {}
    return (
        -get_rack_candidate_value(rack),
        -_to_int(rack.get('bonus') or 0),
        -_to_int(((rack.get('rack_info') or {}).get('height')) or 0),
        str(rack.get('name') or ''),
        str(rack.get('_id') or rack.get('rack_id') or '')
    )


def build_full_rack_placement_plan(room_data, strategy='value'):
    room_data = ensure_room_data_augmented(room_data)
    grid = get_room_rack_grid_info(room_data)
    slot_list = []
    for y in range(grid['slotRows']):
        for x in range(grid['slotCols']):
            slot_list.append({'x': x, 'y': y, 'rackIndex': (y * grid['slotCols']) + x, 'user_room_id': grid['userRoomId'], 'room_level': grid['roomLevel']})

    current_racks = [dict(r, source='room') for r in (room_data.get('racks') or [])]
    inventory_racks = expand_inventory_rack_items(room_data.get('rackInventoryItems') or [])
    all_candidates = current_racks + inventory_racks

    def sort_key_value(r):
        return rack_cmp_tuple(r)

    def sort_key_bonus_first(r):
        return (-_to_int(r.get('bonus') or 0), -_to_int(((r.get('rack_info') or {}).get('height')) or 0), *rack_cmp_tuple(r)[3:])

    def sort_key_height_first(r):
        return (-_to_int(((r.get('rack_info') or {}).get('height')) or 0), -_to_int(r.get('bonus') or 0), *rack_cmp_tuple(r)[3:])

    key_fn = sort_key_value if strategy == 'value' else (sort_key_bonus_first if strategy == 'bonus-first' else sort_key_height_first)
    all_candidates = sorted(all_candidates, key=key_fn)
    selected_racks = all_candidates[:len(slot_list)]
    placements = []
    for index, rack in enumerate(selected_racks):
        placements.append({'rack': {**rack, '_virtualRackId': f'virtual-rack-{index}'}, 'slot': slot_list[index]})

    return {
        'strategy': strategy,
        'grid': grid,
        'slotList': slot_list,
        'currentRacks': current_racks,
        'inventoryRacks': inventory_racks,
        'selectedRacks': selected_racks,
        'placements': placements,
        'rackIdsToClear': [r.get('_id') for r in current_racks if r.get('_id')]
    }


def build_virtual_room_data_for_plan(room_data, rack_plan):
    virtual_racks = []
    for index, item in enumerate(rack_plan.get('placements') or []):
        rack = dict(item.get('rack') or {})
        slot = item.get('slot') or {}
        rack['_id'] = rack.get('_virtualRackId') or f'virtual-rack-{index}'
        rack['placement'] = {
            'x': _to_int(slot.get('x') or 0),
            'y': _to_int(slot.get('y') or 0),
            'rackIndex': _to_int(slot.get('rackIndex') or index),
            'user_room_id': slot.get('user_room_id') or '',
            'room_level': _to_int(slot.get('room_level') or 0)
        }
        virtual_racks.append(rack)
    out = dict(room_data or {})
    out['racks'] = virtual_racks
    out['miners'] = []
    return out


def build_miner_row_targets(room_data):
    rows = []
    for rack in (room_data.get('racks') or []):
        height = _to_int(((rack.get('rack_info') or {}).get('height')) or 0)
        bonus = _to_int(rack.get('bonus') or 0)
        placement = rack.get('placement') or {}
        for y in range(height):
            rows.append({
                'rackId': rack.get('_id'),
                'rackName': rack.get('name') or 'Rack',
                'bonus': bonus,
                'row': y,
                'rackHeight': height,
                'roomX': _to_int(placement.get('x') or 0),
                'roomY': _to_int(placement.get('y') or 0)
            })
    return rows


def row_sort_key(row, strategy='bonus-desc'):
    if strategy == 'rack-grouped':
        return (-_to_int(row.get('bonus') or 0), -_to_int(row.get('rackHeight') or 0), _to_int(row.get('roomX') or 0), _to_int(row.get('roomY') or 0), _to_int(row.get('row') or 0))
    if strategy == 'tall-first':
        return (-_to_int(row.get('rackHeight') or 0), -_to_int(row.get('bonus') or 0), _to_int(row.get('roomY') or 0), _to_int(row.get('roomX') or 0), _to_int(row.get('row') or 0))
    return (-_to_int(row.get('bonus') or 0), _to_int(row.get('roomY') or 0), _to_int(row.get('roomX') or 0), _to_int(row.get('row') or 0))


def miner_sort_key(miner, strategy='power'):
    power = calculate_miner_base_effective_power(miner)
    width = max(1, _to_int(miner.get('width') or 1))
    density = power / width
    base = []
    if strategy == 'density':
        base.append(-density)
    base.append(-power)
    base.append(width if strategy == 'single-priority' else -width)
    base.append(str(miner.get('name') or ''))
    base.append(str(miner.get('_id') or miner.get('miner_id') or ''))
    return tuple(base)


def build_miner_auto_plan(room_data, row_strategy='bonus-desc', miner_strategy='power'):
    row_targets = sorted(build_miner_row_targets(room_data), key=lambda row: row_sort_key(row, row_strategy))
    miners = [dict(m) for m in (room_data.get('minersAll') or room_data.get('miners') or [])]
    width_one = sorted([m for m in miners if _to_int(m.get('width') or 1) <= 1], key=lambda m: miner_sort_key(m, miner_strategy))
    width_two = sorted([m for m in miners if _to_int(m.get('width') or 1) >= 2], key=lambda m: miner_sort_key(m, miner_strategy))
    multipliers = [1 + (normalize_percent_value(row.get('bonus') or 0) / 100.0) for row in row_targets]

    states = {'0|0': {'score': 0.0, 'prev': None, 'choice': None}}
    layers = [states]
    for row_index in range(len(row_targets)):
        next_states = {}
        multiplier = multipliers[row_index] if row_index < len(multipliers) else 1

        def put_state(key, candidate):
            existing = next_states.get(key)
            if existing is None or candidate['score'] > existing['score']:
                next_states[key] = candidate

        for key, state in states.items():
            used_two, used_one = [int(x) for x in key.split('|')]
            put_state(f'{used_two}|{used_one}', {'score': state['score'], 'prev': key, 'choice': {'type': 'empty', 'rowIndex': row_index}})
            if used_two < len(width_two):
                miner = width_two[used_two]
                put_state(f'{used_two + 1}|{used_one}', {'score': state['score'] + (calculate_miner_base_effective_power(miner) * multiplier), 'prev': key, 'choice': {'type': 'double', 'rowIndex': row_index, 'miners': [miner]}})
            if used_one < len(width_one):
                miner = width_one[used_one]
                put_state(f'{used_two}|{used_one + 1}', {'score': state['score'] + (calculate_miner_base_effective_power(miner) * multiplier), 'prev': key, 'choice': {'type': 'single', 'rowIndex': row_index, 'miners': [miner]}})
            if (used_one + 1) < len(width_one):
                miner_a = width_one[used_one]
                miner_b = width_one[used_one + 1]
                pair_score = state['score'] + ((calculate_miner_base_effective_power(miner_a) + calculate_miner_base_effective_power(miner_b)) * multiplier)
                put_state(f'{used_two}|{used_one + 2}', {'score': pair_score, 'prev': key, 'choice': {'type': 'pair', 'rowIndex': row_index, 'miners': [miner_a, miner_b]}})
        states = next_states
        layers.append(states)

    best_key = '0|0'
    best_state = {'score': float('-inf')}
    for key, state in states.items():
        if state['score'] > best_state['score']:
            best_state = state
            best_key = key

    selected_rows = []
    for row_index in range(len(row_targets), 0, -1):
        layer = layers[row_index]
        state = layer.get(best_key)
        if not state:
            break
        if state.get('choice') and state['choice'].get('type') != 'empty':
            selected_rows.append(state['choice'])
        best_key = state.get('prev')
        if best_key is None:
            break
    selected_rows.reverse()

    assignments = []
    for choice in selected_rows:
        row_target = row_targets[choice['rowIndex']]
        for miner_index, miner in enumerate(choice.get('miners') or []):
            width = max(1, _to_int(miner.get('width') or 1))
            assignments.append({
                'miner': miner,
                'target': row_target,
                'placement': {'user_rack_id': row_target['rackId'], 'x': 0 if width >= 2 else miner_index, 'y': row_target['row']},
                'boostedPower': calculate_rack_boosted_power(miner, row_target.get('bonus') or 0)
            })

    assigned_ids = {str((item.get('miner') or {}).get('_id') or '') for item in assignments if (item.get('miner') or {}).get('_id')}
    skipped_miners = [miner for miner in miners if str(miner.get('_id') or '') not in assigned_ids]
    return {
        'assignments': assignments,
        'rowTargets': row_targets,
        'skippedMiners': skipped_miners,
        'rowStrategy': row_strategy,
        'minerStrategy': miner_strategy,
        'totalRawPower': sum(_to_int((item.get('miner') or {}).get('power') or 0) for item in assignments),
        'totalMinerAdjustedPower': sum(calculate_miner_base_effective_power(item.get('miner') or {}) for item in assignments),
        'totalBoostedPower': sum(_to_int(item.get('boostedPower') or 0) for item in assignments)
    }


def build_best_miner_arrangement(room_data):
    room_data = ensure_room_data_augmented(room_data)
    candidates = []
    for rack_strategy in ['value', 'bonus-first', 'height-first']:
        rack_plan = build_full_rack_placement_plan(room_data, rack_strategy)
        virtual_room_data = build_virtual_room_data_for_plan({**room_data, 'minersAll': [dict(m) for m in (room_data.get('minersAll') or room_data.get('miners') or [])]}, rack_plan)
        for row_strategy in ['bonus-desc', 'rack-grouped', 'tall-first']:
            for miner_strategy in ['power', 'density', 'single-priority']:
                plan = build_miner_auto_plan(virtual_room_data, row_strategy, miner_strategy)
                candidates.append({'label': f'{rack_strategy}|{row_strategy}|{miner_strategy}', 'rackStrategy': rack_strategy, 'rowStrategy': row_strategy, 'minerStrategy': miner_strategy, 'rackPlan': rack_plan, 'virtualRoomData': virtual_room_data, 'plan': plan})

    candidates.sort(key=lambda c: (-_to_int(((c.get('plan') or {}).get('totalBoostedPower')) or 0), _to_int(len(((c.get('plan') or {}).get('skippedMiners') or []))), -_to_int(((c.get('plan') or {}).get('totalRawPower')) or 0), str(c.get('label') or '')))
    for index, candidate in enumerate(candidates):
        candidate['rank'] = index + 1
    return {'best': candidates[0] if candidates else None, 'candidates': candidates}


def summarize_current_miner_layout(room_data):
    rack_map = {rack.get('_id'): rack for rack in (room_data.get('racks') or [])}
    total_raw_power = sum(_to_int(miner.get('power') or 0) for miner in (room_data.get('miners') or []))
    total_miner_adjusted_power = sum(calculate_miner_base_effective_power(miner) for miner in (room_data.get('miners') or []))
    total_boosted_power = 0
    for miner in (room_data.get('miners') or []):
        rack = rack_map.get(((miner.get('placement') or {}).get('user_rack_id')))
        total_boosted_power += calculate_rack_boosted_power(miner, (rack or {}).get('bonus') or 0)
    return {'totalRawPower': total_raw_power, 'totalMinerAdjustedPower': total_miner_adjusted_power, 'totalBoostedPower': total_boosted_power}


def build_miner_plan_payload(room_data):
    room_data = ensure_room_data_augmented(room_data)
    arrangement = build_best_miner_arrangement(room_data)
    source_key = f"{len(room_data.get('minersAll') or [])}:{len(room_data.get('racks') or [])}"
    arrangement['sourceKey'] = source_key
    return {'summary': summarize_current_miner_layout(room_data), 'arrangement': arrangement, 'sourceKey': source_key}


@app.route('/api/miner/bootstrap', methods=['GET'])
def api_miner_bootstrap():
    bot_auth, error = require_bot_identity(request)
    if error:
        return error
    return jsonify({
        'success': True,
        'enabled': True,
        'mode': 'server-brain-required',
        'uid': bot_auth['uid'],
        'routes': {
            'arrange_plan': '/api/miner/arrange-plan',
            'room_config': 'https://rollercoin.com/api/game/room-config/{uid}',
            'inventory_miner': 'https://rollercoin.com/api/game/inventory?itemType=miner&search=&sort=updated&skip={skip}&limit={limit}&sort_direction=-1&type=miner',
            'inventory_rack': 'https://rollercoin.com/api/game/inventory?itemType=rack&search=&sort=updated&skip={skip}&limit={limit}&sort_direction=-1&type=rack',
            'user_power_data': 'https://rollercoin.com/api/profile/user-power-data',
            'move_miners_to_inventory': 'https://rollercoin.com/api/game/move-miners-to-inventory',
            'move_racks_to_inventory': 'https://rollercoin.com/api/game/move-racks-to-inventory',
            'move_racks_from_inventory': 'https://rollercoin.com/api/game/move-racks-from-inventory',
            'move_miners_from_inventory': 'https://rollercoin.com/api/game/move-miners-from-inventory'
        },
        'timing': {
            'move_out_miners_min_ms': 900,
            'move_out_miners_max_ms': 1400,
            'move_out_racks_min_ms': 1100,
            'move_out_racks_max_ms': 1700,
            'place_rack_min_ms': 260,
            'place_rack_max_ms': 520,
            'post_rack_refresh_min_ms': 1100,
            'post_rack_refresh_max_ms': 1700,
            'place_miner_min_ms': 260,
            'place_miner_max_ms': 520
        }
    })


@app.route('/api/miner/arrange-plan', methods=['POST'])
@limiter.limit("30 per minute")
def api_miner_arrange_plan():
    bot_auth, error = require_bot_identity(request)
    if error:
        return error
    data = request.get_json() or {}
    uid = str(data.get('uid') or data.get('user_id') or '').strip().lower()
    room_data = data.get('room_data') or data.get('roomData') or {}
    if not uid:
        return jsonify({'success': False, 'error': 'uid gerekli'})
    if uid != bot_auth['uid']:
        return jsonify({'success': False, 'error': 'uid uyusmuyor'}), 401
    if not isinstance(room_data, dict) or not isinstance(room_data.get('racks') or [], list):
        return jsonify({'success': False, 'error': 'room_data gerekli'})
    try:
        payload = build_miner_plan_payload(room_data)
        log_event(f'Miner plan hesaplandi: {uid[:8]}... racks={len((room_data.get("racks") or []))} miners={len((room_data.get("minersAll") or room_data.get("miners") or []))}')
        return jsonify({'success': True, **payload})
    except Exception as e:
        log_event(f'Miner plan hatasi: {e}')
        return jsonify({'success': False, 'error': str(e)})


def valid_session(user, token):
    token = str(token or '').strip()
    if not token:
        return False
    return any(secure_equals(str(s.get('token') or '').strip(), token) for s in (user.get('sessions') or []))


def get_latest_uid(users=None):
    users = users or load_json(USERS_FILE, {})
    latest_uid = ''
    latest_time = ''
    for uid, row in users.items():
        tm = str(row.get('last_login') or row.get('created') or '')
        if tm >= latest_time:
            latest_time = tm
            latest_uid = uid
    return latest_uid


@app.route('/')
def index():
    return jsonify({'success': True, 'service': 'server-local-online-api', 'status': 'ok'})


@app.route('/api/health')
def api_health():
    return jsonify({'success': True, 'time': datetime.now().isoformat()})


@app.route('/api/public-links', methods=['GET'])
def api_public_links():
    return jsonify({'success': True, 'quick_links': load_quick_links()})


@app.route('/api/auth', methods=['POST'])
@limiter.limit("10 per minute")
def api_auth():
    data = request.get_json() or {}
    uid = str(data.get('uid') or '').strip().lower()
    license_key = str(data.get('license_key') or '').strip()
    name = str(data.get('name') or 'Kullanici').strip() or 'Kullanici'
    language = normalize_lang(data.get('language', 'tr'))
    fingerprint = str(data.get('fingerprint') or '').strip()
    incoming_client_id = str(data.get('client_id') or '').strip()
    incoming_hash = str(data.get('script_hash') or '').strip()
    android_mode = bool(data.get('android_mode', False))

    if not uid or not license_key:
        return jsonify({'success': False, 'error': 'Eksik bilgi'})
    if len(license_key) > MAX_LICENSE_KEY_LENGTH:
        return jsonify({'success': False, 'error': 'Lisans anahtari cok uzun'})
    if not is_safe_text(name):
        return jsonify({'success': False, 'error': 'Gecersiz isim'})
    if not is_safe_text(incoming_client_id):
        return jsonify({'success': False, 'error': 'Gecersiz client id'})
    if not re.match(r'^[a-f0-9]{24}$', uid, re.IGNORECASE):
        return jsonify({'success': False, 'error': 'Gecersiz UID'})

    decrypted = decrypt_license_for_server(license_key)
    if not decrypted:
        return jsonify({'success': False, 'error': 'Lisans gecersiz'})

    license_id = str(decrypted.get('license_id') or '').strip()
    client_name = str(decrypted.get('client_name') or name).strip() or name
    client_id = str(decrypted.get('client_id') or incoming_client_id).strip()
    if not license_id:
        return jsonify({'success': False, 'error': 'Lisans kaydi yok'})
    if is_revoked_license(license_id, license_key, client_id, incoming_hash):
        return jsonify({'success': False, 'error': 'Script gecersiz'})

    licenses = load_json(LICENSES_FILE, {})
    if license_id not in licenses:
        licenses[license_id] = {
            'license_id': license_id,
            'client_name': client_name,
            'client_id': client_id,
            'issued_at': str(decrypted.get('issued_at') or datetime.now().isoformat()),
            'uid': None,
            'active': True,
            'status': 'active',
            'script_hash': client_hash_text(client_name + '|' + client_id),
            'last_heartbeat': None,
            'encrypted_license': license_key,
            'telegram_token': '',
            'telegram_chat_id': ''
        }

    row = licenses[license_id]
    client_ip = get_request_ip(request)
    row = check_license_anomaly(row, uid, fingerprint, client_ip)
    if not row.get('active', True):
        return jsonify({'success': False, 'error': 'Lisans pasif'})

    if client_id and row.get('client_id') and client_id != row.get('client_id'):
        return jsonify({'success': False, 'error': 'Script kimligi uyusmuyor'})

    expected_hash = str(row.get('script_hash') or '').strip()
    if expected_hash and incoming_hash and incoming_hash != expected_hash:
        return jsonify({'success': False, 'error': 'Script dogrulamasi basarisiz'})

    bound_uid = str(row.get('uid') or '').strip().lower()
    users = load_json(USERS_FILE, {})
    allow_uid_change = bool(row.get('allow_uid_change', True))
    if not bound_uid:
        row['uid'] = uid
    elif bound_uid != uid:
        if not allow_uid_change:
            return jsonify({'success': False, 'error': 'Script gecersiz'})
        row['old_uid'] = bound_uid
        row['uid'] = uid
        row['rebind_at'] = datetime.now().isoformat()
        users.pop(bound_uid, None)

    session_token = secrets.token_hex(16)
    if uid not in users:
        users[uid] = {
            'uid': uid,
            'name': client_name,
            'license_id': license_id,
            'fingerprint': fingerprint,
            'created': datetime.now().isoformat(),
            'sessions': [],
            'seen_notice_ids': []
        }
    users[uid]['last_login'] = datetime.now().isoformat()
    users[uid]['license_id'] = license_id
    users[uid]['language'] = language
    users[uid].setdefault('sessions', []).append({
        'token': session_token,
        'fingerprint': fingerprint,
        'time': datetime.now().isoformat()
    })
    users[uid]['sessions'] = (users[uid].get('sessions') or [])[-MAX_SESSIONS_PER_USER:]

    row['language'] = language
    row['last_login'] = datetime.now().isoformat()
    row['last_ip'] = client_ip
    save_json(USERS_FILE, users)
    save_json(LICENSES_FILE, licenses)

    bot_code = load_variant_bot_content(android_mode)
    if bot_code and android_mode:
        bot_code = apply_android_bot_patch(bot_code)
    if bot_code:
        bot_code = patch_bot_content(bot_code)
        bot_code = bot_code.replace('__VIP_SCRIPT_CLIENT_ID__', client_id or '')
        bot_code = bot_code.replace('__VIP_SCRIPT_HASH__', str(row.get('script_hash') or incoming_hash or ''))
        bot_code = bot_code.replace('__VIP_SCRIPT_SESSION__', session_token)
        bot_code = bot_code.replace('__VIP_SCRIPT_BOT_TOKEN__', '')
        bot_code = bot_code.replace('__VIP_SCRIPT_UID__', uid)
    payload = {
        'success': True,
        'session_token': session_token,
        'uid': uid,
        'language': language,
        'quick_links': load_quick_links(),
        'android_mode': android_mode,
    }
    if bot_code:
        payload['bot_code'] = encrypt_bot_for_uid(bot_code, uid)
        payload['bot_variant'] = 'android' if android_mode else 'desktop'
    log_event(f"Auth ok: {uid[:8]}... -> {license_id} / {'android' if android_mode else 'desktop'}")
    return jsonify(payload)


@app.route('/api/heartbeat', methods=['POST'])
@limiter.limit("120 per minute")
def api_heartbeat():
    data = request.get_json() or {}
    token = str(data.get('token') or '').strip()
    uid = str(data.get('uid') or '').strip().lower()
    incoming_client_id = str(data.get('client_id') or '').strip()
    incoming_hash = str(data.get('script_hash') or '').strip()
    if not token or not uid:
        return jsonify({'success': False, 'error': 'Eksik heartbeat'})

    users = load_json(USERS_FILE, {})
    licenses = load_json(LICENSES_FILE, {})
    user = users.get(uid)
    if not user or not valid_session(user, token):
        return jsonify({'success': False, 'error': 'off'})
    license_id = user.get('license_id')
    row = licenses.get(license_id or '')
    if not row or not row.get('active', True):
        return jsonify({'success': False, 'error': 'off'})
    if str(row.get('uid') or '').strip().lower() != uid:
        return jsonify({'success': False, 'error': 'invalid uid'})
    if row.get('client_id') and incoming_client_id and incoming_client_id != row.get('client_id'):
        return jsonify({'success': False, 'error': 'off'})
    if row.get('script_hash') and incoming_hash and incoming_hash != row.get('script_hash'):
        return jsonify({'success': False, 'error': 'off'})
    row['last_heartbeat'] = datetime.now().isoformat()
    licenses[license_id] = row
    save_json(LICENSES_FILE, licenses)
    return jsonify({'success': True})


@app.route('/api/telegram/register', methods=['POST'])
@limiter.limit("10 per minute")
def api_telegram_register():
    data = request.get_json() or {}
    token = str(data.get('token') or '').strip()
    uid = str(data.get('uid') or '').strip().lower()
    telegram_token = str(data.get('telegram_token') or '').strip()
    telegram_chat_id = str(data.get('telegram_chat_id') or '').strip()
    if not token or not uid or not telegram_token or not telegram_chat_id:
        return jsonify({'success': False, 'error': 'Eksik Telegram bilgisi'})
    if not is_safe_text(telegram_token) or not is_safe_text(telegram_chat_id, 256):
        return jsonify({'success': False, 'error': 'Telegram bilgisi gecersiz'})

    users = load_json(USERS_FILE, {})
    user = users.get(uid)
    if not user or not valid_session(user, token):
        return jsonify({'success': False, 'error': 'Gecersiz oturum'})
    licenses = load_json(LICENSES_FILE, {})
    license_id = user.get('license_id')
    row = licenses.get(license_id or '')
    if not row:
        return jsonify({'success': False, 'error': 'Lisans bulunamadi'})

    ok, resp = send_telegram_api(telegram_token, 'getMe', {})
    if not ok:
        return jsonify({'success': False, 'error': 'Telegram bot token gecersiz', 'detail': resp})

    row['telegram_token'] = telegram_token
    row['telegram_chat_id'] = telegram_chat_id
    row['telegram_connected_at'] = datetime.now().isoformat()
    licenses[license_id] = row
    save_json(LICENSES_FILE, licenses)
    send_license_telegram_menu(row)
    return jsonify({'success': True, 'bot': resp.get('result', {})})


@app.route('/api/client/command', methods=['POST'])
@limiter.limit("120 per minute")
def api_client_command():
    data = request.get_json() or {}
    token = str(data.get('token') or '').strip()
    uid = str(data.get('uid') or '').strip().lower()
    if not token or not uid:
        return jsonify({'success': False, 'error': 'Eksik bilgi'})
    users = load_json(USERS_FILE, {})
    user = users.get(uid)
    if not user or not valid_session(user, token):
        return jsonify({'success': False, 'error': 'Gecersiz oturum'})
    licenses = load_json(LICENSES_FILE, {})
    license_id = user.get('license_id')
    row = licenses.get(license_id or '') or {}
    if str(row.get('uid') or '').strip().lower() != uid:
        return jsonify({'success': False, 'error': 'Script gecersiz'})
    command = client_pending_commands.pop(0) if client_pending_commands else None
    return jsonify({'success': True, 'command': command})


@app.route('/api/bot/bootstrap-check', methods=['POST'])
@limiter.limit("60 per minute")
def api_bot_bootstrap_check():
    data = request.get_json() or {}
    uid = str(request.headers.get('X-VIP-UID') or data.get('uid') or '').strip().lower()
    session_token = str(request.headers.get('X-VIP-Session-Token') or '').strip()
    client_id = str(request.headers.get('X-VIP-Client-ID') or '').strip()
    if not uid or not session_token or not client_id:
        return jsonify({'success': False, 'error': 'kimlik eksik'}), 401
    users = load_json(USERS_FILE, {})
    licenses = load_json(LICENSES_FILE, {})
    user = users.get(uid)
    if not user or not valid_session(user, session_token):
        return jsonify({'success': False, 'error': 'gecersiz oturum'}), 401
    license_id = user.get('license_id')
    row = licenses.get(license_id or '') or {}
    if not row or not row.get('active', True):
        return jsonify({'success': False, 'error': 'off'}), 401
    if str(row.get('uid') or '').strip().lower() != uid:
        return jsonify({'success': False, 'error': 'script gecersiz'}), 401
    if str(row.get('client_id') or '').strip() != client_id:
        return jsonify({'success': False, 'error': 'script kimligi uyusmuyor'}), 401
    return jsonify({'success': True, 'uid': uid, 'client_id': client_id})


@app.route('/games', methods=['GET'])
def api_games():
    bot_auth, error = require_bot_identity(request)
    if error:
        return error
    return jsonify(normalize_games_map(load_json(GAMES_FILE, {})))


@app.route('/user_id', methods=['GET'])
def api_user_id_get():
    users = load_json(USERS_FILE, {})
    return jsonify({'success': True, 'user_id': get_latest_uid(users)})


@app.route('/user_id', methods=['POST'])
def api_user_id_set():
    data = request.get_json() or {}
    uid = str(data.get('user_id') or data.get('uid') or '').strip().lower()
    if not uid or not re.match(r'^[a-f0-9]{24}$', uid, re.IGNORECASE):
        return jsonify({'success': False, 'message': 'Geçerli user id bulunamadı'})
    users = load_json(USERS_FILE, {})
    users.setdefault(uid, {'uid': uid, 'name': data.get('source', 'script'), 'created': datetime.now().isoformat(), 'sessions': []})
    save_json(USERS_FILE, users)
    return jsonify({'success': True, 'user_id': uid, 'message': 'Aktif user id güncellendi'})


@app.route('/encrypt', methods=['POST'])
def api_encrypt():
    try:
        data = request.get_json() or {}
        uid = str(data.get('uid') or data.get('user_id') or '').strip().lower()
        if not uid:
            uid = get_latest_uid()
        if not uid:
            return jsonify({'success': False, 'error': 'uid gerekli'})
        payload = {
            'power': int(data['power']),
            'time': int(data['time']),
            'user_game_id': str(data['user_game_id']),
            'win_status': int(data.get('win_status', 3))
        }
        encrypted = encrypt_with_uid(payload, uid)
        return jsonify({'success': True, 'encrypted': encrypted, 'user_id': uid})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/encrypt_start', methods=['POST'])
def api_encrypt_start():
    try:
        data = request.get_json() or {}
        uid = str(data.get('uid') or data.get('user_id') or '').strip().lower()
        start_data = data.get('start_data')
        if not uid:
            return jsonify({'success': False, 'error': 'uid gerekli'})
        if start_data in (None, ''):
            return jsonify({'success': False, 'error': 'start_data gerekli'})
        encrypted = encrypt_with_uid(start_data, uid)
        return jsonify({'success': True, 'encrypted': encrypted, 'user_id': uid})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/notify', methods=['POST'])
def api_notify():
    bot_auth, error = require_bot_identity(request)
    if error:
        return error
    data = request.get_json() or {}
    log_event(f"Notify[{bot_auth['uid'][:8]}]: {json.dumps(data, ensure_ascii=False)[:500]}")
    return jsonify({'success': True, 'received': data})


@app.route('/bot/status', methods=['POST'])
def api_bot_status():
    global last_bot_status
    bot_auth, error = require_bot_identity(request)
    if error:
        return error
    try:
        data = request.get_json() or {}
        last_bot_status = {
            'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'uid': bot_auth['uid'],
            'license_id': bot_auth['license_id'],
            'is_running': bool(data.get('is_running', False)),
            'is_paused': bool(data.get('is_paused', False)),
            'is_playing': bool(data.get('is_playing', False)),
            'pending_end_request': bool(data.get('pending_end_request', False)),
            'current_game': data.get('current_game') or data.get('current_game_name') or data.get('playing_game'),
            'current_level': data.get('current_level'),
            'status_text': str(data.get('status_text') or 'Hazır'),
            'total_loaded_games': int(data.get('total_loaded_games', 0) or 0),
            'ready_games_count': int(data.get('ready_games_count', 0) or 0),
            'total_played_games': int(data.get('total_played_games', 0) or 0),
            'total_power': int(data.get('total_power', 0) or 0),
            'instant_power': int(data.get('instant_power', data.get('current_power', 0)) or 0),
            'remaining_seconds': int(data.get('remaining_seconds', data.get('time_left', data.get('remaining_time', 0))) or 0)
        }
        return jsonify({'success': True, 'status': last_bot_status})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/bot/status', methods=['GET'])
def api_bot_status_get():
    return jsonify({'success': True, 'status': last_bot_status})


@app.route('/bot/command', methods=['GET'])
def api_bot_command_get():
    bot_auth, error = require_bot_identity(request)
    if error:
        return error
    command = pending_commands.pop(0) if pending_commands else None
    return jsonify({'success': True, 'command': command, 'uid': bot_auth['uid']})


@app.route('/bot/command', methods=['POST'])
def api_bot_command_post():
    data = request.get_json() or {}
    command = str(data.get('command') or '').strip().lower()
    if command not in {'start','stop','reset','refresh','full_clean','status','menu','games','reset_stats'}:
        return jsonify({'success': False, 'message': 'Geçersiz komut'})
    pending_commands.append({
        'command': 'reset' if command == 'refresh' else command,
        'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'source': 'manual'
    })
    return jsonify({'success': True, 'command': command, 'status': last_bot_status})


@app.route('/bot/command/ack', methods=['POST'])
def api_bot_command_ack():
    bot_auth, error = require_bot_identity(request)
    if error:
        return error
    return jsonify({'success': True, 'uid': bot_auth['uid']})


@app.route('/api/notice/ack', methods=['POST'])
def api_notice_ack():
    data = request.get_json() or {}
    token = str(data.get('token') or '').strip()
    uid = str(data.get('uid') or '').strip().lower()
    notice_id = str(data.get('notice_id') or '').strip()
    if not token or not uid or not notice_id:
        return jsonify({'success': False, 'error': 'Eksik ack bilgisi'})
    users = load_json(USERS_FILE, {})
    user = users.get(uid)
    if not user or not valid_session(user, token):
        return jsonify({'success': False, 'error': 'Gecersiz oturum'})
    user.setdefault('seen_notice_ids', [])
    if notice_id not in user['seen_notice_ids']:
        user['seen_notice_ids'].append(notice_id)
    user.setdefault('seen_personal_notice_ids', [])
    if notice_id not in user['seen_personal_notice_ids']:
        user['seen_personal_notice_ids'].append(notice_id)
    user['delivered_notice_ids'] = [x for x in (user.get('delivered_notice_ids') or []) if x != notice_id]
    user['delivered_personal_notice_ids'] = [x for x in (user.get('delivered_personal_notice_ids') or []) if x != notice_id]
    user['personal_notice'] = {}
    users[uid] = user
    save_json(USERS_FILE, users)
    licenses = load_json(LICENSES_FILE, {})
    license_id = user.get('license_id')
    if license_id in licenses and str(licenses[license_id].get('message_id') or '') == notice_id:
        licenses[license_id]['message_status'] = 'Okundu'
        licenses[license_id]['personal_notice'] = {}
        save_json(LICENSES_FILE, licenses)
    return jsonify({'success': True})


@app.route('/api/telegram/screenshot', methods=['POST'])
@limiter.limit("10 per minute")
def api_telegram_screenshot():
    data = request.get_json() or {}
    token = str(data.get('token') or '').strip()
    uid = str(data.get('uid') or '').strip().lower()
    image = str(data.get('image') or '').strip()
    if not token or not uid or not image:
        return jsonify({'success': False, 'error': 'Eksik ekran bilgisi'})
    if len(image) > MAX_SCREENSHOT_B64_LENGTH:
        return jsonify({'success': False, 'error': 'Ekran verisi cok buyuk'})
    users = load_json(USERS_FILE, {})
    user = users.get(uid)
    if not user or not valid_session(user, token):
        return jsonify({'success': False, 'error': 'Gecersiz oturum'})
    licenses = load_json(LICENSES_FILE, {})
    license_id = user.get('license_id')
    row = licenses.get(license_id or '') or {}
    if str(row.get('uid') or '').strip().lower() != uid:
        return jsonify({'success': False, 'error': 'Script gecersiz'})
    tg_token = str(row.get('telegram_token') or '').strip()
    tg_chat = str(row.get('telegram_chat_id') or '').strip()
    lang = str(row.get('language') or user.get('language') or 'tr').strip().lower()
    if not tg_token or not tg_chat:
        return jsonify({'success': False, 'error': 'Telegram bagli degil'})
    allowed, limit_state, retry_at = check_screenshot_rate_limit(license_id)
    if not allowed:
        if limit_state == 'blocked_new':
            retry_text = format_retry_time(retry_at)
            send_telegram_api(tg_token, 'sendMessage', {
                'chat_id': tg_chat,
                'text': screenshot_block_message_by_lang(lang, retry_text)
            })
            log_event(f'Screenshot block aktif: {license_id} / yeniden acilma {retry_text}')
            return jsonify({'success': False, 'error': 'Cok fazla ekran alma istegi. 1 saat engellendi', 'retry_at': retry_text})
        if limit_state == 'blocked':
            return jsonify({'success': False, 'error': 'Ekran alma gecici olarak engelli', 'retry_at': format_retry_time(retry_at)})
        remaining = max(1, int(retry_at - time.time()))
        return jsonify({'success': False, 'error': f'Ekran alma limiti var. {remaining} sn sonra tekrar dene', 'retry_at': format_retry_time(retry_at)})
    if ',' in image:
        image = image.split(',', 1)[1]
    try:
        photo_bytes = base64.b64decode(image)
    except Exception:
        return jsonify({'success': False, 'error': 'Ekran verisi bozuk'})
    ok, resp = send_telegram_photo(tg_token, tg_chat, photo_bytes, screenshot_caption_by_lang(lang))
    if not ok:
        return jsonify({'success': False, 'error': 'Telegrama gonderilemedi', 'detail': resp})
    return jsonify({'success': True})


@app.route('/api/notice/next', methods=['POST'])
@limiter.limit("60 per minute")
def api_notice_next():
    data = request.get_json() or {}
    token = str(data.get('token') or '').strip()
    uid = str(data.get('uid') or '').strip().lower()
    if not token or not uid:
        return jsonify({'success': False, 'error': 'Eksik uid'})
    users = load_json(USERS_FILE, {})
    user = users.get(uid)
    if not user or not valid_session(user, token):
        return jsonify({'success': False, 'error': 'Gecersiz oturum'})

    licenses = load_json(LICENSES_FILE, {})
    license_id = user.get('license_id')
    row = licenses.get(license_id or '') or {}
    if str(row.get('uid') or '').strip().lower() != uid:
        return jsonify({'success': False, 'error': 'Script gecersiz'})

    personal = (row.get('personal_notice') or user.get('personal_notice') or {})
    if personal.get('id') and personal.get('text'):
        seen_personal = user.get('seen_personal_notice_ids', []) or []
        delivered_personal = user.get('delivered_personal_notice_ids', []) or []
        if personal['id'] not in seen_personal and personal['id'] not in delivered_personal:
            user.setdefault('delivered_personal_notice_ids', []).append(personal['id'])
            users[uid] = user
            save_json(USERS_FILE, users)
            if license_id in licenses:
                licenses[license_id]['message_status'] = 'Gonderildi'
                licenses[license_id]['message_text'] = personal.get('text', '')
                licenses[license_id]['message_id'] = personal.get('id', '')
                save_json(LICENSES_FILE, licenses)
            personal_with_links = dict(personal)
            personal_with_links['links'] = personal.get('links') or {}
            return jsonify({'success': True, 'notice': personal_with_links})

    notice = load_json(NOTICE_FILE, {'id': '', 'text': '', 'created_at': ''})
    if not notice.get('id') or not notice.get('text'):
        return jsonify({'success': True, 'notice': None})
    seen = user.get('seen_notice_ids', []) or []
    delivered = user.get('delivered_notice_ids', []) or []
    if notice['id'] in seen or notice['id'] in delivered:
        return jsonify({'success': True, 'notice': None})
    user.setdefault('delivered_notice_ids', []).append(notice['id'])
    licenses = load_json(LICENSES_FILE, {})
    license_id = user.get('license_id')
    if license_id in licenses:
        licenses[license_id]['message_status'] = 'Gonderildi'
        licenses[license_id]['message_text'] = notice.get('text', '')
        licenses[license_id]['message_id'] = notice.get('id', '')
        save_json(LICENSES_FILE, licenses)
    users[uid] = user
    save_json(USERS_FILE, users)
    notice_with_links = dict(notice)
    notice_with_links['links'] = notice.get('links') or {}
    return jsonify({'success': True, 'notice': notice_with_links})


@app.route('/admin/licenses', methods=['GET'])
@limiter.limit("30 per minute")
def admin_licenses():
    if not check_admin(request):
        return jsonify({'success': False, 'error': 'Yetkisiz'}), 401
    licenses = load_json(LICENSES_FILE, {})
    now = datetime.now()
    result = {}
    for lid, row in licenses.items():
        row_copy = dict(row or {})
        is_online = is_license_online(row_copy, now)
        row_copy['runtime_online'] = is_online
        row_copy['display_uid'] = str(row_copy.get('uid') or '').strip() if is_online else ''
        result[lid] = row_copy
    return jsonify({'success': True, 'licenses': result})


@app.route('/admin/users', methods=['GET'])
@limiter.limit("30 per minute")
def admin_users():
    if not check_admin(request):
        return jsonify({'success': False, 'error': 'Yetkisiz'}), 401
    return jsonify({'success': True, 'users': load_json(USERS_FILE, {})})


@app.route('/admin/license/create', methods=['POST'])
@limiter.limit("30 per minute")
def admin_license_create():
    if not check_admin(request):
        return jsonify({'success': False, 'error': 'Yetkisiz'}), 401
    data = request.get_json() or {}
    license_id = str(data.get('license_id') or '').strip()
    client_name = str(data.get('client_name') or 'Kullanici').strip() or 'Kullanici'
    client_id = str(data.get('client_id') or '').strip()
    encrypted_license = str(data.get('encrypted_license') or '').strip()
    script_hash = str(data.get('script_hash') or '').strip()
    script_file = str(data.get('script_file') or '').strip()
    allow_uid_change = bool(data.get('allow_uid_change', True))
    if not license_id or not client_id or not encrypted_license:
        return jsonify({'success': False, 'error': 'Eksik lisans bilgisi'})
    licenses = load_json(LICENSES_FILE, {})
    licenses[license_id] = {
        'license_id': license_id,
        'client_name': client_name,
        'client_id': client_id,
        'issued_at': datetime.now().isoformat(),
        'uid': None,
        'active': True,
        'status': 'active',
        'allow_uid_change': allow_uid_change,
        'script_hash': script_hash or client_hash_text(client_name + '|' + client_id),
        'last_heartbeat': None,
        'script_file': script_file,
        'encrypted_license': encrypted_license,
        'suspicious_reason': '',
        'telegram_token': '',
        'telegram_chat_id': '',
        'message_text': '',
        'message_status': '',
        'message_id': ''
    }
    save_json(LICENSES_FILE, licenses)
    log_admin_action('license_create', license_id, {'client_name': client_name, 'script_file': script_file})
    log_event(f'Admin lisans olusturdu: {license_id}')
    return jsonify({'success': True, 'license': licenses[license_id]})


@app.route('/admin/license/state', methods=['POST'])
@limiter.limit("30 per minute")
def admin_license_state():
    if not check_admin(request):
        return jsonify({'success': False, 'error': 'Yetkisiz'}), 401
    data = request.get_json() or {}
    license_id = str(data.get('license_id') or '').strip()
    active = bool(data.get('active', True))
    if not license_id:
        return jsonify({'success': False, 'error': 'Lisans yok'})
    licenses = load_json(LICENSES_FILE, {})
    row = licenses.get(license_id)
    if not row:
        return jsonify({'success': False, 'error': 'Lisans bulunamadi'})
    row['active'] = active
    row['status'] = 'active' if active else 'inactive'
    if active:
        row['suspicious_reason'] = ''
    licenses[license_id] = row
    save_json(LICENSES_FILE, licenses)
    log_admin_action('license_state', license_id, {'active': active})
    log_event(f'Admin lisans durum degistirdi: {license_id} -> {active}')
    return jsonify({'success': True, 'license': row})


@app.route('/admin/license/uid-mode', methods=['POST'])
@limiter.limit("30 per minute")
def admin_license_uid_mode():
    if not check_admin(request):
        return jsonify({'success': False, 'error': 'Yetkisiz'}), 401
    data = request.get_json() or {}
    license_id = str(data.get('license_id') or '').strip()
    allow_uid_change = bool(data.get('allow_uid_change', True))
    if not license_id:
        return jsonify({'success': False, 'error': 'Lisans yok'})
    licenses = load_json(LICENSES_FILE, {})
    row = licenses.get(license_id)
    if not row:
        return jsonify({'success': False, 'error': 'Lisans bulunamadi'})
    row['allow_uid_change'] = allow_uid_change
    licenses[license_id] = row
    save_json(LICENSES_FILE, licenses)
    log_admin_action('license_uid_mode', license_id, {'allow_uid_change': allow_uid_change})
    log_event(f'Admin uid modu degisti: {license_id} -> allow_uid_change={allow_uid_change}')
    return jsonify({'success': True, 'license': row})


@app.route('/admin/license/delete', methods=['POST'])
@limiter.limit("30 per minute")
def admin_license_delete():
    if not check_admin(request):
        return jsonify({'success': False, 'error': 'Yetkisiz'}), 401
    data = request.get_json() or {}
    license_id = str(data.get('license_id') or '').strip()
    if not license_id:
        return jsonify({'success': False, 'error': 'Lisans yok'})
    licenses = load_json(LICENSES_FILE, {})
    row = licenses.pop(license_id, None)
    if not row:
        return jsonify({'success': False, 'error': 'Lisans bulunamadi'})
    revoked = load_revoked_licenses()
    revoked.append({
        'license_id': license_id,
        'encrypted_license': str(row.get('encrypted_license') or '').strip(),
        'client_id': str(row.get('client_id') or '').strip(),
        'script_hash': str(row.get('script_hash') or '').strip(),
        'deleted_at': datetime.now().isoformat()
    })
    save_revoked_licenses(revoked)
    bound_uid = str(row.get('uid') or '').strip().lower()
    users = load_json(USERS_FILE, {})
    if bound_uid and bound_uid in users:
        users.pop(bound_uid, None)
        save_json(USERS_FILE, users)
    save_json(LICENSES_FILE, licenses)
    log_admin_action('license_delete', license_id, {'bound_uid': bound_uid})
    log_event(f'Admin lisans sildi: {license_id}')
    return jsonify({'success': True})


@app.route('/admin/notice', methods=['POST'])
@limiter.limit("20 per minute")
def admin_notice():
    if not check_admin(request):
        return jsonify({'success': False, 'error': 'Yetkisiz'}), 401
    data = request.get_json() or {}
    text = str(data.get('text') or '').strip()
    links = data.get('links') or {}
    if not text:
        return jsonify({'success': False, 'error': 'Mesaj bos'})
    if len(text) > MAX_NOTICE_TEXT_LENGTH:
        return jsonify({'success': False, 'error': 'Mesaj cok uzun'})
    notice = {
        'id': datetime.now().strftime('%Y%m%d%H%M%S'),
        'text': text,
        'created_at': datetime.now().isoformat(),
        'links': {
            'telegram': str(links.get('telegram') or '').strip(),
            'youtube': str(links.get('youtube') or '').strip(),
            'normal': str(links.get('normal') or '').strip()
        }
    }
    save_json(NOTICE_FILE, notice)
    licenses = load_json(LICENSES_FILE, {})
    for lid in licenses:
        licenses[lid]['message_text'] = text
        licenses[lid]['message_status'] = 'Gonderildi'
        licenses[lid]['message_id'] = notice['id']
    save_json(LICENSES_FILE, licenses)
    log_admin_action('global_notice', '', {'text_preview': text[:80]})
    log_event('Admin notice guncellendi')
    return jsonify({'success': True, 'notice': notice})


@app.route('/admin/notice/user', methods=['POST'])
@limiter.limit("20 per minute")
def admin_notice_user():
    if not check_admin(request):
        return jsonify({'success': False, 'error': 'Yetkisiz'}), 401
    data = request.get_json() or {}
    uid = str(data.get('uid') or '').strip().lower()
    license_id = str(data.get('license_id') or '').strip()
    text = str(data.get('text') or '').strip()
    links = data.get('links') or {}
    if not text or (not uid and not license_id):
        return jsonify({'success': False, 'error': 'Uid veya lisans ve mesaj gerekli'})
    if len(text) > MAX_NOTICE_TEXT_LENGTH:
        return jsonify({'success': False, 'error': 'Mesaj cok uzun'})
    users = load_json(USERS_FILE, {})
    licenses = load_json(LICENSES_FILE, {})
    if not license_id and uid:
        user = users.get(uid)
        if not user:
            return jsonify({'success': False, 'error': 'Kullanici bulunamadi'})
        license_id = str(user.get('license_id') or '').strip()
    row = licenses.get(license_id)
    if not row:
        return jsonify({'success': False, 'error': 'Lisans bulunamadi'})
    notice = {
        'id': datetime.now().strftime('%Y%m%d%H%M%S') + '_' + secrets.token_hex(3),
        'text': text,
        'created_at': datetime.now().isoformat(),
        'scope': 'personal',
        'links': {
            'telegram': str(links.get('telegram') or '').strip(),
            'youtube': str(links.get('youtube') or '').strip(),
            'normal': str(links.get('normal') or '').strip()
        }
    }
    row['personal_notice'] = notice
    row['message_text'] = text
    row['message_status'] = 'Gonderildi'
    row['message_id'] = notice['id']
    licenses[license_id] = row
    save_json(LICENSES_FILE, licenses)
    log_admin_action('personal_notice', license_id, {'uid': uid, 'text_preview': text[:80]})
    log_event(f'Admin ozel mesaj gonderdi: {license_id}')
    return jsonify({'success': True, 'notice': notice})


@app.route('/admin/bot', methods=['GET'])
@limiter.limit("20 per minute")
def admin_bot_get():
    if not check_admin(request):
        return jsonify({'success': False, 'error': 'Yetkisiz'}), 401
    variant = str(request.args.get('variant') or 'desktop').strip().lower()
    is_android = variant == 'android'
    bot_content = load_variant_bot_content(is_android)
    return jsonify({'success': True, 'variant': 'android' if is_android else 'desktop', 'bot_size': len(str(bot_content or ''))})


@app.route('/admin/bot', methods=['POST'])
@limiter.limit("10 per minute")
def admin_bot_set():
    if not check_admin(request):
        return jsonify({'success': False, 'error': 'Yetkisiz'}), 401
    data = request.get_json() or {}
    variant = str(data.get('variant') or 'desktop').strip().lower()
    is_android = variant == 'android'
    content = str(data.get('content') or '')
    if not content:
        return jsonify({'success': False, 'error': 'Bot icerigi bos'})
    if len(content) > (2 * 1024 * 1024):
        return jsonify({'success': False, 'error': 'Bot icerigi cok buyuk'})
    save_variant_bot_content(content, is_android)
    log_admin_action('bot_update', '', {'variant': 'android' if is_android else 'desktop', 'size': len(content)})
    log_event(f"Admin bot guncelledi: {'android' if is_android else 'desktop'}")
    return jsonify({'success': True, 'variant': 'android' if is_android else 'desktop'})


@app.route('/admin/games', methods=['GET'])
@limiter.limit("20 per minute")
def admin_games_get():
    if not check_admin(request):
        return jsonify({'success': False, 'error': 'Yetkisiz'}), 401
    return jsonify({'success': True, 'games': load_json(GAMES_FILE, {})})


@app.route('/admin/games', methods=['POST'])
@limiter.limit("10 per minute")
def admin_games_set():
    if not check_admin(request):
        return jsonify({'success': False, 'error': 'Yetkisiz'}), 401
    data = request.get_json() or {}
    games = data.get('games') or {}
    if not isinstance(games, dict):
        return jsonify({'success': False, 'error': 'Gecersiz games verisi'})
    games = normalize_games_map(games)
    save_json(GAMES_FILE, games)
    log_admin_action('games_update', '', {'count': len(games)})
    log_event(f'Admin games guncelledi: {len(games)} oyun')
    return jsonify({'success': True, 'count': len(games)})


@app.route('/admin/bot-command', methods=['POST'])
@limiter.limit("30 per minute")
def admin_bot_command():
    if not check_admin(request):
        return jsonify({'success': False, 'error': 'Yetkisiz'}), 401
    data = request.get_json() or {}
    command = str(data.get('command') or '').strip().lower()
    if not command:
        return jsonify({'success': False, 'error': 'Komut bos'})
    pending_commands.append({'command': command, 'time': datetime.now().isoformat(), 'source': 'admin'})
    log_admin_action('bot_command', '', {'command': command})
    return jsonify({'success': True})


@app.route('/admin/client-command', methods=['POST'])
@limiter.limit("30 per minute")
def admin_client_command():
    if not check_admin(request):
        return jsonify({'success': False, 'error': 'Yetkisiz'}), 401
    data = request.get_json() or {}
    command = str(data.get('command') or '').strip()
    if not command:
        return jsonify({'success': False, 'error': 'Komut bos'})
    client_pending_commands.append({'command': command, 'time': datetime.now().isoformat(), 'source': 'admin'})
    log_admin_action('client_command', '', {'command': command})
    return jsonify({'success': True})


@app.route('/admin/clear-all', methods=['POST'])
@limiter.limit("10 per minute")
def admin_clear_all():
    if not check_admin(request):
        return jsonify({'success': False, 'error': 'Yetkisiz'}), 401
    data = request.get_json() or {}
    keep_bots = bool(data.get('keep_bots', True))
    keep_games = bool(data.get('keep_games', True))
    keep_links = bool(data.get('keep_links', True))
    save_json(LICENSES_FILE, {})
    save_json(USERS_FILE, {})
    save_json(REVOKED_LICENSES_FILE, [])
    save_json(NOTICE_FILE, {'id': '', 'text': '', 'created_at': '', 'links': {}})
    if not keep_games:
        save_json(GAMES_FILE, {})
    if not keep_links:
        save_quick_links({'active': False, 'telegram': '', 'youtube': '', 'normal': ''})
    if not keep_bots:
        save_variant_bot_content('', False)
        save_variant_bot_content('', True)
    pending_commands.clear()
    client_pending_commands.clear()
    log_admin_action('clear_all', '', {'keep_bots': keep_bots, 'keep_games': keep_games, 'keep_links': keep_links})
    log_event('Admin full temizleme yapti')
    return jsonify({'success': True})


@app.route('/admin/sync-all', methods=['POST'])
@limiter.limit("20 per minute")
def admin_sync_all():
    if not check_admin(request):
        return jsonify({'success': False, 'error': 'Yetkisiz'}), 401
    data = request.get_json() or {}
    licenses = data.get('licenses') or {}
    users = data.get('users') or {}
    notice = data.get('notice')
    bot_content = data.get('bot_content')
    bot_android_content = data.get('bot_android_content')
    games = data.get('games') or {}
    quick_links = data.get('quick_links') or {}

    if not isinstance(licenses, dict) or not isinstance(users, dict):
        return jsonify({'success': False, 'error': 'Gecersiz sync verisi'})

    save_json(LICENSES_FILE, licenses)
    save_json(USERS_FILE, users)
    save_json(GAMES_FILE, normalize_games_map(games if isinstance(games, dict) else {}))
    if isinstance(quick_links, dict):
        save_quick_links(quick_links)
    if isinstance(notice, dict):
        save_json(NOTICE_FILE, notice)
    if isinstance(bot_content, str) and bot_content.strip():
        save_variant_bot_content(bot_content, False)
    if isinstance(bot_android_content, str) and bot_android_content.strip():
        save_variant_bot_content(bot_android_content, True)

    log_admin_action('sync_all', '', {
        'licenses_count': len(licenses),
        'users_count': len(users),
        'games_count': len(games) if isinstance(games, dict) else 0,
        'bot': bool(isinstance(bot_content, str) and bot_content.strip()),
        'bot_android': bool(isinstance(bot_android_content, str) and bot_android_content.strip())
    })
    log_event(f"Admin tam senkron yapti: licenses={len(licenses)} users={len(users)} games={len(games) if isinstance(games, dict) else 0} bot={'var' if isinstance(bot_content, str) and bot_content.strip() else 'yok'} android_bot={'var' if isinstance(bot_android_content, str) and bot_android_content.strip() else 'yok'}")
    return jsonify({'success': True, 'licenses_count': len(licenses), 'users_count': len(users)})


if __name__ == '__main__':
    log_event('Server basladi')
    verify_bot_files()
    if not ADMIN_TOKEN:
        log_event('UYARI: ADMIN_TOKEN bos.')
    telegram_thread = threading.Thread(target=poll_all_telegram_bots, daemon=True)
    telegram_thread.start()
    app.run(host=HOST, port=PORT, debug=False)
