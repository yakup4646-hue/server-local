#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import base64
import hashlib
import secrets
import re
import threading
from datetime import datetime
from io import BytesIO
from urllib import request as urlrequest
from urllib.error import URLError, HTTPError
from urllib.parse import quote
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from config import (
    HOST, PORT, ADMIN_TOKEN, SERVER_LICENSE_SECRET, SUPABASE_URL, SUPABASE_SERVICE_KEY, ALLOWED_ORIGINS,
    USERS_FILE, LICENSES_FILE, NOTICE_FILE, LOGS_FILE, BOT_FILE, GAMES_FILE
)

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": ALLOWED_ORIGINS or "*"}})

IV = b'dYQ9R99bkKLsLHad'
LICENSE_SECRET = (hashlib.sha256(SERVER_LICENSE_SECRET.encode('utf-8')).digest()[:32]
                  if SERVER_LICENSE_SECRET else
                  hashlib.sha256(b"ROLLER_VIP_SERVER_ONLY_SECRET_2026").digest()[:32])
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
    str(GAMES_FILE): 'games',
}


def _supabase_enabled():
    return bool(SUPABASE_URL and SUPABASE_SERVICE_KEY)


def _supabase_headers():
    return {
        'apikey': SUPABASE_SERVICE_KEY,
        'Authorization': f'Bearer {SUPABASE_SERVICE_KEY}',
        'Content-Type': 'application/json'
    }


def _supabase_get_state(state_key, default):
    if not _supabase_enabled():
        return default
    try:
        url = f"{SUPABASE_URL}/rest/v1/app_state?key=eq.{quote(state_key)}&select=value"
        req = urlrequest.Request(url, headers=_supabase_headers(), method='GET')
        with urlrequest.urlopen(req, timeout=20) as resp:
            rows = json.loads(resp.read().decode('utf-8'))
        if rows and isinstance(rows, list):
            return rows[0].get('value', default)
    except Exception as e:
        log_event(f'Supabase load error ({state_key}): {e}')
    return default


def _supabase_set_state(state_key, value):
    if not _supabase_enabled():
        return False
    try:
        body = json.dumps({
            'key': state_key,
            'value': value,
            'updated_at': datetime.now().isoformat()
        }).encode('utf-8')
        headers = _supabase_headers()
        headers['Prefer'] = 'resolution=merge-duplicates'
        url = f"{SUPABASE_URL}/rest/v1/app_state?on_conflict=key"
        req = urlrequest.Request(url, data=body, headers=headers, method='POST')
        with urlrequest.urlopen(req, timeout=20) as resp:
            resp.read()
        return True
    except Exception as e:
        log_event(f'Supabase save error ({state_key}): {e}')
        return False


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


def check_admin(req):
    token = str(req.headers.get('X-Admin-Token') or req.args.get('admin_token') or '').strip()
    return bool(ADMIN_TOKEN) and token == ADMIN_TOKEN


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


def patch_bot_content(content: str):
    server_url = request.host_url.rstrip('/')
    content = re.sub(r"const\s+PY_URL\s*=\s*['\"]http://127\.0\.0\.1:\d+['\"]\s*;", f"const PY_URL = '{server_url}';", content)
    content = content.replace('__SERVER_URL__', server_url)
    content = content.replace('http://127.0.0.1:5003', server_url)
    content = content.replace('http://127.0.0.1:5005', server_url)
    return content


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


def build_license_telegram_menu(_license_id=None):
    return {
        'keyboard': [
            ['🎮 Bot Durumu'],
            ['▶️ Başlat', '⏹️ Durdur'],
            ['🧹 İstatistik Sıfırla']
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
                    elif text in {'🧹 i̇statistik sıfırla', '🧹 istatistik sıfırla', '🧹 istatistik sifirla'}:
                        process_telegram_action(row, 'reset_stats')
            if changed:
                log_event('Telegram polling aktif')
        except Exception as e:
            log_event(f'Telegram polling error: {e}')
        threading.Event().wait(5)


def valid_session(user, token):
    return any(str(s.get('token') or '').strip() == token for s in (user.get('sessions') or []))


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


@app.route('/api/auth', methods=['POST'])
def api_auth():
    data = request.get_json() or {}
    uid = str(data.get('uid') or '').strip().lower()
    license_key = str(data.get('license_key') or '').strip()
    name = str(data.get('name') or 'Kullanici').strip() or 'Kullanici'
    language = normalize_lang(data.get('language', 'tr'))
    fingerprint = str(data.get('fingerprint') or '').strip()
    incoming_client_id = str(data.get('client_id') or '').strip()
    incoming_hash = str(data.get('script_hash') or '').strip()

    if not uid or not license_key:
        return jsonify({'success': False, 'error': 'Eksik bilgi'})
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
    if not row.get('active', True):
        return jsonify({'success': False, 'error': 'Lisans pasif'})

    if client_id and row.get('client_id') and client_id != row.get('client_id'):
        return jsonify({'success': False, 'error': 'Script kimligi uyusmuyor'})

    expected_hash = str(row.get('script_hash') or '').strip()
    if expected_hash and incoming_hash and incoming_hash != expected_hash:
        return jsonify({'success': False, 'error': 'Script dogrulamasi basarisiz'})

    bound_uid = str(row.get('uid') or '').strip().lower()
    users = load_json(USERS_FILE, {})
    if not bound_uid:
        row['uid'] = uid
    elif bound_uid != uid:
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

    row['language'] = language
    row['last_login'] = datetime.now().isoformat()
    save_json(USERS_FILE, users)
    save_json(LICENSES_FILE, licenses)

    bot_code = load_json(BOT_FILE, '')
    if not isinstance(bot_code, str):
        bot_code = BOT_FILE.read_text(encoding='utf-8', errors='ignore') if BOT_FILE.exists() else ''
    if bot_code:
        bot_code = patch_bot_content(bot_code)
    payload = {
        'success': True,
        'session_token': session_token,
        'uid': uid,
        'language': language,
    }
    if bot_code:
        payload['bot_code'] = encrypt_bot_for_uid(bot_code, uid)
    log_event(f'Auth ok: {uid[:8]}... -> {license_id}')
    return jsonify(payload)


@app.route('/api/heartbeat', methods=['POST'])
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
def api_telegram_register():
    data = request.get_json() or {}
    token = str(data.get('token') or '').strip()
    uid = str(data.get('uid') or '').strip().lower()
    telegram_token = str(data.get('telegram_token') or '').strip()
    telegram_chat_id = str(data.get('telegram_chat_id') or '').strip()
    if not token or not uid or not telegram_token or not telegram_chat_id:
        return jsonify({'success': False, 'error': 'Eksik Telegram bilgisi'})

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
    command = client_pending_commands.pop(0) if client_pending_commands else None
    return jsonify({'success': True, 'command': command})


@app.route('/games', methods=['GET'])
def api_games():
    return jsonify(load_json(GAMES_FILE, {}))


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


@app.route('/notify', methods=['POST'])
def api_notify():
    data = request.get_json() or {}
    log_event(f"Notify: {json.dumps(data, ensure_ascii=False)[:500]}")
    return jsonify({'success': True, 'received': data})


@app.route('/bot/status', methods=['POST'])
def api_bot_status():
    global last_bot_status
    try:
        data = request.get_json() or {}
        last_bot_status = {
            'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
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
    command = pending_commands.pop(0) if pending_commands else None
    return jsonify({'success': True, 'command': command})


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
    return jsonify({'success': True})


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
def api_telegram_screenshot():
    data = request.get_json() or {}
    token = str(data.get('token') or '').strip()
    uid = str(data.get('uid') or '').strip().lower()
    image = str(data.get('image') or '').strip()
    if not token or not uid or not image:
        return jsonify({'success': False, 'error': 'Eksik ekran bilgisi'})
    users = load_json(USERS_FILE, {})
    user = users.get(uid)
    if not user or not valid_session(user, token):
        return jsonify({'success': False, 'error': 'Gecersiz oturum'})
    licenses = load_json(LICENSES_FILE, {})
    license_id = user.get('license_id')
    row = licenses.get(license_id or '') or {}
    tg_token = str(row.get('telegram_token') or '').strip()
    tg_chat = str(row.get('telegram_chat_id') or '').strip()
    if not tg_token or not tg_chat:
        return jsonify({'success': False, 'error': 'Telegram bagli degil'})
    if ',' in image:
        image = image.split(',', 1)[1]
    try:
        photo_bytes = base64.b64decode(image)
    except Exception:
        return jsonify({'success': False, 'error': 'Ekran verisi bozuk'})
    ok, resp = send_telegram_photo(tg_token, tg_chat, photo_bytes, 'Roller VIP ekran goruntusu')
    if not ok:
        return jsonify({'success': False, 'error': 'Telegrama gonderilemedi', 'detail': resp})
    return jsonify({'success': True})


@app.route('/api/notice/next', methods=['POST'])
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
            return jsonify({'success': True, 'notice': personal})

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
    return jsonify({'success': True, 'notice': notice})


@app.route('/admin/licenses', methods=['GET'])
def admin_licenses():
    if not check_admin(request):
        return jsonify({'success': False, 'error': 'Yetkisiz'}), 401
    licenses = load_json(LICENSES_FILE, {})
    now = datetime.now()
    for lid, row in licenses.items():
        hb = str(row.get('last_heartbeat') or '').strip()
        is_online = False
        if hb:
            try:
                is_online = (now - datetime.fromisoformat(hb)).total_seconds() <= 90
            except Exception:
                is_online = False
        row['runtime_online'] = is_online
        licenses[lid] = row
    return jsonify({'success': True, 'licenses': licenses})


@app.route('/admin/users', methods=['GET'])
def admin_users():
    if not check_admin(request):
        return jsonify({'success': False, 'error': 'Yetkisiz'}), 401
    return jsonify({'success': True, 'users': load_json(USERS_FILE, {})})


@app.route('/admin/license/create', methods=['POST'])
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
    log_event(f'Admin lisans olusturdu: {license_id}')
    return jsonify({'success': True, 'license': licenses[license_id]})


@app.route('/admin/license/state', methods=['POST'])
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
    log_event(f'Admin lisans durum degistirdi: {license_id} -> {active}')
    return jsonify({'success': True, 'license': row})


@app.route('/admin/license/delete', methods=['POST'])
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
    bound_uid = str(row.get('uid') or '').strip().lower()
    users = load_json(USERS_FILE, {})
    if bound_uid and bound_uid in users:
        users.pop(bound_uid, None)
        save_json(USERS_FILE, users)
    save_json(LICENSES_FILE, licenses)
    log_event(f'Admin lisans sildi: {license_id}')
    return jsonify({'success': True})


@app.route('/admin/notice', methods=['POST'])
def admin_notice():
    if not check_admin(request):
        return jsonify({'success': False, 'error': 'Yetkisiz'}), 401
    data = request.get_json() or {}
    text = str(data.get('text') or '').strip()
    if not text:
        return jsonify({'success': False, 'error': 'Mesaj bos'})
    notice = {'id': datetime.now().strftime('%Y%m%d%H%M%S'), 'text': text, 'created_at': datetime.now().isoformat()}
    save_json(NOTICE_FILE, notice)
    licenses = load_json(LICENSES_FILE, {})
    for lid in licenses:
        licenses[lid]['message_text'] = text
        licenses[lid]['message_status'] = 'Gonderildi'
        licenses[lid]['message_id'] = notice['id']
    save_json(LICENSES_FILE, licenses)
    log_event('Admin notice guncellendi')
    return jsonify({'success': True, 'notice': notice})


@app.route('/admin/notice/user', methods=['POST'])
def admin_notice_user():
    if not check_admin(request):
        return jsonify({'success': False, 'error': 'Yetkisiz'}), 401
    data = request.get_json() or {}
    uid = str(data.get('uid') or '').strip().lower()
    license_id = str(data.get('license_id') or '').strip()
    text = str(data.get('text') or '').strip()
    if not text or (not uid and not license_id):
        return jsonify({'success': False, 'error': 'Uid veya lisans ve mesaj gerekli'})
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
        'scope': 'personal'
    }
    row['personal_notice'] = notice
    row['message_text'] = text
    row['message_status'] = 'Gonderildi'
    row['message_id'] = notice['id']
    licenses[license_id] = row
    save_json(LICENSES_FILE, licenses)
    log_event(f'Admin ozel mesaj gonderdi: {license_id}')
    return jsonify({'success': True, 'notice': notice})


@app.route('/admin/bot', methods=['GET'])
def admin_bot_get():
    if not check_admin(request):
        return jsonify({'success': False, 'error': 'Yetkisiz'}), 401
    bot_content = load_json(BOT_FILE, '') if _supabase_enabled() else BOT_FILE.read_text(encoding='utf-8', errors='ignore')
    if isinstance(bot_content, dict):
        bot_content = ''
    return jsonify({'success': True, 'bot_size': len(str(bot_content or ''))})


@app.route('/admin/bot', methods=['POST'])
def admin_bot_set():
    if not check_admin(request):
        return jsonify({'success': False, 'error': 'Yetkisiz'}), 401
    data = request.get_json() or {}
    content = str(data.get('content') or '')
    if not content:
        return jsonify({'success': False, 'error': 'Bot icerigi bos'})
    content = re.sub(r"const\s+PY_URL\s*=\s*['\"]http://127\.0\.0\.1:\d+['\"]\s*;", "const PY_URL = '__SERVER_URL__';", content)
    content = content.replace('http://127.0.0.1:5003', '__SERVER_URL__')
    content = content.replace('http://127.0.0.1:5005', '__SERVER_URL__')
    save_json(BOT_FILE, content)
    BOT_FILE.write_text(content, encoding='utf-8')
    log_event('Admin bot guncelledi')
    return jsonify({'success': True})


@app.route('/admin/games', methods=['GET'])
def admin_games_get():
    if not check_admin(request):
        return jsonify({'success': False, 'error': 'Yetkisiz'}), 401
    return jsonify({'success': True, 'games': load_json(GAMES_FILE, {})})


@app.route('/admin/games', methods=['POST'])
def admin_games_set():
    if not check_admin(request):
        return jsonify({'success': False, 'error': 'Yetkisiz'}), 401
    data = request.get_json() or {}
    games = data.get('games') or {}
    if not isinstance(games, dict):
        return jsonify({'success': False, 'error': 'Gecersiz games verisi'})
    save_json(GAMES_FILE, games)
    log_event(f'Admin games guncelledi: {len(games)} oyun')
    return jsonify({'success': True, 'count': len(games)})


@app.route('/admin/bot-command', methods=['POST'])
def admin_bot_command():
    if not check_admin(request):
        return jsonify({'success': False, 'error': 'Yetkisiz'}), 401
    data = request.get_json() or {}
    command = str(data.get('command') or '').strip().lower()
    if not command:
        return jsonify({'success': False, 'error': 'Komut bos'})
    pending_commands.append({'command': command, 'time': datetime.now().isoformat(), 'source': 'admin'})
    return jsonify({'success': True})


@app.route('/admin/client-command', methods=['POST'])
def admin_client_command():
    if not check_admin(request):
        return jsonify({'success': False, 'error': 'Yetkisiz'}), 401
    data = request.get_json() or {}
    command = str(data.get('command') or '').strip()
    if not command:
        return jsonify({'success': False, 'error': 'Komut bos'})
    client_pending_commands.append({'command': command, 'time': datetime.now().isoformat(), 'source': 'admin'})
    return jsonify({'success': True})


@app.route('/admin/sync-all', methods=['POST'])
def admin_sync_all():
    if not check_admin(request):
        return jsonify({'success': False, 'error': 'Yetkisiz'}), 401
    data = request.get_json() or {}
    licenses = data.get('licenses') or {}
    users = data.get('users') or {}
    notice = data.get('notice')
    bot_content = data.get('bot_content')
    games = data.get('games') or {}

    if not isinstance(licenses, dict) or not isinstance(users, dict):
        return jsonify({'success': False, 'error': 'Gecersiz sync verisi'})

    save_json(LICENSES_FILE, licenses)
    save_json(USERS_FILE, users)
    save_json(GAMES_FILE, games if isinstance(games, dict) else {})
    if isinstance(notice, dict):
        save_json(NOTICE_FILE, notice)
    if isinstance(bot_content, str) and bot_content.strip():
        save_json(BOT_FILE, bot_content)
        BOT_FILE.write_text(bot_content, encoding='utf-8')

    log_event(f"Admin tam senkron yapti: licenses={len(licenses)} users={len(users)} games={len(games) if isinstance(games, dict) else 0} bot={'var' if isinstance(bot_content, str) and bot_content.strip() else 'yok'}")
    return jsonify({'success': True, 'licenses_count': len(licenses), 'users_count': len(users)})


if __name__ == '__main__':
    log_event('Server basladi')
    telegram_thread = threading.Thread(target=poll_all_telegram_bots, daemon=True)
    telegram_thread.start()
    app.run(host=HOST, port=PORT, debug=False)
