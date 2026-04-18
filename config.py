import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / 'data'
DATA_DIR.mkdir(exist_ok=True)

HOST = os.getenv('HOST', '127.0.0.1')
PORT = int(os.getenv('PORT', '5005'))
ADMIN_TOKEN = os.getenv('ADMIN_TOKEN', '')
SERVER_LICENSE_SECRET = os.getenv('SERVER_LICENSE_SECRET', '')
SUPABASE_URL = os.getenv('SUPABASE_URL', '').strip()
SUPABASE_SERVICE_KEY = os.getenv('SUPABASE_SERVICE_KEY', '').strip()
ALLOWED_ORIGINS = [x.strip() for x in os.getenv('ALLOWED_ORIGINS', '').split(',') if x.strip()]

USERS_FILE = DATA_DIR / 'users.json'
LICENSES_FILE = DATA_DIR / 'licenses.json'
NOTICE_FILE = DATA_DIR / 'notice.json'
LOGS_FILE = DATA_DIR / 'server_logs.txt'
BOT_FILE = DATA_DIR / 'bot.txt'
BOT_ANDROID_FILE = DATA_DIR / 'bot_android.txt'
GAMES_FILE = DATA_DIR / 'games.json'
REVOKED_LICENSES_FILE = DATA_DIR / 'revoked_licenses.json'
QUICK_LINKS_FILE = DATA_DIR / 'quick_links.json'

for p, default in [
    (USERS_FILE, '{}'),
    (LICENSES_FILE, '{}'),
    (NOTICE_FILE, '{"id":"","text":"","created_at":""}'),
    (LOGS_FILE, ''),
    (BOT_FILE, ''),
    (BOT_ANDROID_FILE, ''),
    (GAMES_FILE, '{}'),
    (REVOKED_LICENSES_FILE, '[]'),
    (QUICK_LINKS_FILE, '{"telegram":"","youtube":""}'),
]:
    if not p.exists():
        p.write_text(default, encoding='utf-8')
