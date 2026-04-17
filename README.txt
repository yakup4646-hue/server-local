server local

Amaç:
- online API server ayrı çalışsın
- yönetim paneli ayrı kalsın
- PC kapalı olsa da server online kalsın

Dosyalar:
- server.py           -> online çalışacak temel API
- admin_gui_note.txt  -> mevcut v.py yönetim paneli notu
- config.py           -> env tabanlı ayarlar
- requirements.txt    -> python paketleri
- .env.example        -> örnek ortam değişkenleri
- deploy/nginx.conf.example
- deploy/roller-vip.service

Not:
- 'ele geçirilmesi imkansız' diye bir garanti yoktur.
- ama güvenli kurulum yapılır:
  - HTTPS
  - reverse proxy
  - env secret
  - firewall
  - rate limit
  - admin token
