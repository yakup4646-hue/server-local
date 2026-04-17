#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify
from flask_cors import CORS
import json
from datetime import datetime
from urllib import request as urlrequest
from urllib.error import URLError, HTTPError
from config import (
    HOST, PORT, ADMIN_TOKEN, ALLOWED_ORIGINS,
    USERS_FILE, LICENSES_FILE, NOTICE_FILE, LOGS_FILE, BOT_FILE
)

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": ALLOWED_ORIGINS or "*"}})


def load_json(path, default):
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except Exception:
        return default


def save_json(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')


def log_event(event):
    with open(LOGS_FILE, 'a', encoding='utf-8') as f:
        f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {event}\n")


def check_admin(req):
    token = str(req.headers.get('X-Admin-Token') or req.args.get('admin_token') or '').strip()
    return bool(ADMIN_TOKEN) and token == ADMIN_TOKEN


@app.route('/')
def index():
    return jsonify({
        'success': True,
        'service': 'server-local-online-api',
        'status': 'ok'
    })


@app.route('/api/health')
def api_health():
    return jsonify({'success': True, 'time': datetime.now().isoformat()})


@app.route('/api/notice/next', methods=['POST'])
def api_notice_next():
    data = request.get_json() or {}
    uid = str(data.get('uid') or '').strip().lower()
    if not uid:
        return jsonify({'success': False, 'error': 'Eksik uid'})
    users = load_json(USERS_FILE, {})
    user = users.get(uid)
    if not user:
        return jsonify({'success': True, 'notice': None})
    notice = load_json(NOTICE_FILE, {'id': '', 'text': '', 'created_at': ''})
    if not notice.get('id') or not notice.get('text'):
        return jsonify({'success': True, 'notice': None})
    seen = user.get('seen_notice_ids', []) or []
    if notice['id'] in seen:
        return jsonify({'success': True, 'notice': None})
    user.setdefault('seen_notice_ids', []).append(notice['id'])
    users[uid] = user
    save_json(USERS_FILE, users)
    return jsonify({'success': True, 'notice': notice})


@app.route('/admin/licenses', methods=['GET'])
def admin_licenses():
    if not check_admin(request):
        return jsonify({'success': False, 'error': 'Yetkisiz'}), 401
    return jsonify({'success': True, 'licenses': load_json(LICENSES_FILE, {})})


@app.route('/admin/notice', methods=['POST'])
def admin_notice():
    if not check_admin(request):
        return jsonify({'success': False, 'error': 'Yetkisiz'}), 401
    data = request.get_json() or {}
    text = str(data.get('text') or '').strip()
    if not text:
        return jsonify({'success': False, 'error': 'Mesaj bos'})
    notice = {
        'id': datetime.now().strftime('%Y%m%d%H%M%S'),
        'text': text,
        'created_at': datetime.now().isoformat()
    }
    save_json(NOTICE_FILE, notice)
    log_event('Admin notice guncellendi')
    return jsonify({'success': True, 'notice': notice})


@app.route('/admin/bot', methods=['GET'])
def admin_bot_get():
    if not check_admin(request):
        return jsonify({'success': False, 'error': 'Yetkisiz'}), 401
    return jsonify({'success': True, 'bot_size': len(BOT_FILE.read_text(encoding='utf-8', errors='ignore'))})


@app.route('/admin/bot', methods=['POST'])
def admin_bot_set():
    if not check_admin(request):
        return jsonify({'success': False, 'error': 'Yetkisiz'}), 401
    data = request.get_json() or {}
    content = str(data.get('content') or '')
    if not content:
        return jsonify({'success': False, 'error': 'Bot icerigi bos'})
    BOT_FILE.write_text(content, encoding='utf-8')
    log_event('Admin bot guncelledi')
    return jsonify({'success': True})


if __name__ == '__main__':
    log_event('Server basladi')
    app.run(host=HOST, port=PORT, debug=False)
