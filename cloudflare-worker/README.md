# Cloudflare Worker deployment

This directory contains the Cloudflare-native API used as an independent
primary or backup server. It does not use a tunnel or a permanently running
container.

Required bindings and secrets:

- D1 binding: `DB`
- Secret: `ADMIN_TOKEN` (same value used by `v.py`)
- Variable: `CLIENT_SERVER_URLS` (comma-separated server URLs)

After creating the D1 database, apply `migrations/0001_init.sql`, add the `DB`
binding in the Worker settings, add `ADMIN_TOKEN`, and redeploy. The desktop
panel can then send the complete bot/license state with `/admin/sync-all`.
