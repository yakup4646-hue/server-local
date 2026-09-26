const CACHE_TTL_MS = 15000;
const stateCache = new Map();
let schemaReady = false;

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type, X-Admin-Token, X-VIP-UID, X-VIP-Session-Token, X-VIP-Client-ID, X-VIP-Script-Hash, X-VIP-Bot-Token",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...CORS },
  });
}

function nowIso() {
  return new Date().toISOString();
}

function cleanUrl(value) {
  const url = String(value || "").trim().replace(/\/+$/, "");
  return /^https:\/\/[a-z0-9.-]+(?::\d+)?$/i.test(url) ? url : "";
}

function clientHash(text) {
  let h = 0;
  for (const ch of String(text || "")) h = ((h << 5) - h + ch.charCodeAt(0)) | 0;
  return `h${Math.abs(h).toString(16)}`;
}

function randomToken() {
  return crypto.randomUUID().replaceAll("-", "") + crypto.randomUUID().replaceAll("-", "").slice(0, 8);
}

async function ensureDb(env) {
  if (!env.DB) throw new Error("D1 DB binding eksik");
  if (schemaReady) return;
  await env.DB.exec("CREATE TABLE IF NOT EXISTS app_state (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL)");
  schemaReady = true;
}

async function readState(env, key, fallback) {
  await ensureDb(env);
  const cached = stateCache.get(key);
  if (cached && Date.now() - cached.at < CACHE_TTL_MS) return structuredClone(cached.value);
  const row = await env.DB.prepare("SELECT value FROM app_state WHERE key = ? LIMIT 1").bind(key).first();
  let value = fallback;
  if (row?.value != null) {
    try { value = JSON.parse(row.value); } catch {}
  }
  stateCache.set(key, { at: Date.now(), value: structuredClone(value) });
  return structuredClone(value);
}

async function writeState(env, key, value) {
  await ensureDb(env);
  const encoded = JSON.stringify(value);
  await env.DB.prepare(
    "INSERT INTO app_state (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at"
  ).bind(key, encoded, nowIso()).run();
  stateCache.set(key, { at: Date.now(), value: structuredClone(value) });
}

async function bodyJson(request) {
  try { return await request.json(); } catch { return {}; }
}

function isAdmin(request, env) {
  const supplied = String(request.headers.get("X-Admin-Token") || "");
  return Boolean(env.ADMIN_TOKEN) && supplied === String(env.ADMIN_TOKEN);
}

function normalizeLinks(value) {
  const data = value && typeof value === "object" ? value : {};
  return {
    active: Boolean(data.active),
    telegram: String(data.telegram || ""),
    youtube: String(data.youtube || ""),
    login: String(data.login || ""),
    normal: String(data.normal || ""),
  };
}

function validSession(user, token) {
  return Boolean(token) && Array.isArray(user?.sessions) && user.sessions.some((item) => String(item?.token || "") === String(token));
}

async function botIdentity(request, env) {
  const uid = String(request.headers.get("X-VIP-UID") || "").trim().toLowerCase();
  const token = String(request.headers.get("X-VIP-Session-Token") || "").trim();
  const clientId = String(request.headers.get("X-VIP-Client-ID") || "").trim();
  if (!uid || !token || !clientId) return { error: json({ success: false, error: "kimlik eksik" }, 401) };
  const [users, licenses] = await Promise.all([
    readState(env, "users", {}),
    readState(env, "licenses", {}),
  ]);
  const user = users[uid];
  const row = licenses[user?.license_id || ""];
  if (!user || !validSession(user, token) || !row || row.active === false) {
    return { error: json({ success: false, error: "session expired" }, 401) };
  }
  if (String(row.uid || "").toLowerCase() !== uid || String(row.client_id || "") !== clientId) {
    return { error: json({ success: false, error: "script gecersiz" }, 401) };
  }
  return { uid, token, clientId, user, row, users, licenses };
}

function bytesToBase64(bytes) {
  let binary = "";
  const size = 0x8000;
  for (let i = 0; i < bytes.length; i += size) {
    binary += String.fromCharCode(...bytes.subarray(i, Math.min(i + size, bytes.length)));
  }
  return btoa(binary);
}

function encryptBotForUid(source, uid) {
  const src = new TextEncoder().encode(source);
  const key = new TextEncoder().encode(uid);
  const out = new Uint8Array(src.length);
  for (let i = 0; i < src.length; i++) out[i] = src[i] ^ key[i % key.length];
  return bytesToBase64(out);
}

function patchBot(source, origin) {
  return String(source || "")
    .replace(/const\s+PY_URL\s*=\s*['"]http:\/\/127\.0\.0\.1:\d+['"]\s*;/g, `const PY_URL = '${origin}';`)
    .replaceAll("__SERVER_URL__", origin)
    .replaceAll("http://127.0.0.1:5003", origin)
    .replaceAll("http://127.0.0.1:5005", origin);
}

async function activeRedirect(request, env, origin) {
  const path = new URL(request.url).pathname;
  if (!path.startsWith("/api/") || ["/api/health", "/api/client-config"].includes(path)) return null;
  const target = await readState(env, "server_target", {});
  const active = cleanUrl(target?.active_server_url);
  if (!active || active === origin) return null;
  return json({ success: false, error: "Sunucu gecisi gerekli", active_server_url: active }, 503);
}

async function authenticate(request, env, origin) {
  const data = await bodyJson(request);
  const uid = String(data.uid || "").trim().toLowerCase();
  const key = String(data.license_key || "").trim();
  const incomingClientId = String(data.client_id || "").trim();
  const incomingHash = String(data.script_hash || "").trim();
  if (!/^[a-f0-9]{24}$/i.test(uid) || !key) return json({ success: false, error: "Eksik veya gecersiz bilgi" });

  const [licenses, users, revoked, links] = await Promise.all([
    readState(env, "licenses", {}),
    readState(env, "users", {}),
    readState(env, "revoked_licenses", []),
    readState(env, "quick_links", {}),
  ]);
  if (revoked.some((item) => String(item?.encrypted_license || "") === key || String(item?.client_id || "") === incomingClientId)) {
    return json({ success: false, error: "Script gecersiz" });
  }
  const entry = Object.entries(licenses).find(([, row]) => String(row?.encrypted_license || "") === key);
  if (!entry) return json({ success: false, error: "Lisans kaydi yok" });
  const [licenseId, row] = entry;
  if (row.active === false) return json({ success: false, error: "Lisans pasif" });
  if (row.client_id && incomingClientId && String(row.client_id) !== incomingClientId) return json({ success: false, error: "Script kimligi uyusmuyor" });
  const canonicalHash = clientHash(`${row.client_name || data.name || "Kullanici"}|${row.client_id || incomingClientId}`);
  if (incomingHash && canonicalHash !== incomingHash) return json({ success: false, error: "Script dogrulamasi basarisiz" });
  const boundUid = String(row.uid || "").toLowerCase();
  if (boundUid && boundUid !== uid && row.allow_uid_change === false) return json({ success: false, error: "Script gecersiz" });
  if (boundUid && boundUid !== uid) delete users[boundUid];

  row.uid = uid;
  row.client_id = row.client_id || incomingClientId;
  row.script_hash = canonicalHash;
  row.language = ["tr", "en", "pr"].includes(String(data.language || "").toLowerCase()) ? String(data.language).toLowerCase() : "tr";
  row.last_login = nowIso();
  const sessionToken = randomToken();
  const user = users[uid] || { uid, created: nowIso(), sessions: [], seen_notice_ids: [], seen_personal_notice_ids: [] };
  user.name = row.client_name || data.name || "Kullanici";
  user.license_id = licenseId;
  user.language = row.language;
  user.last_login = nowIso();
  user.sessions = [...(user.sessions || []).filter((item) => item?.token), { token: sessionToken, fingerprint: String(data.fingerprint || ""), time: nowIso() }].slice(-20);
  users[uid] = user;
  licenses[licenseId] = row;
  await Promise.all([writeState(env, "licenses", licenses), writeState(env, "users", users)]);

  const variant = data.android_mode ? "bot_android" : "bot";
  let bot = await readState(env, variant, "");
  if (!bot && variant === "bot_android") bot = await readState(env, "bot", "");
  if (!String(bot || "").trim()) return json({ success: false, error: "Bot dosyasi serverda bos, panelden senkron gerekli" });
  bot = patchBot(bot, origin);
  return json({
    success: true,
    session_token: sessionToken,
    uid,
    language: row.language,
    quick_links: normalizeLinks(links),
    android_mode: Boolean(data.android_mode),
    bot_variant: data.android_mode ? "android" : "desktop",
    bot_code: encryptBotForUid(bot, uid),
  });
}

async function heartbeat(request, env) {
  const data = await bodyJson(request);
  const uid = String(data.uid || "").toLowerCase();
  const [users, licenses] = await Promise.all([readState(env, "users", {}), readState(env, "licenses", {})]);
  const user = users[uid];
  const row = licenses[user?.license_id || ""];
  if (!user || !validSession(user, data.token)) return json({ success: false, error: "session expired" });
  if (!row || row.active === false || String(row.uid || "").toLowerCase() !== uid) return json({ success: false, error: "license inactive" });
  if (row.client_id && data.client_id && row.client_id !== data.client_id) return json({ success: false, error: "client id mismatch" });
  const last = Date.parse(row.last_heartbeat || 0) || 0;
  if (Date.now() - last >= 180000) {
    row.last_heartbeat = nowIso();
    licenses[user.license_id] = row;
    await writeState(env, "licenses", licenses);
  }
  return json({ success: true });
}

async function registerTelegram(request, env) {
  const data = await bodyJson(request);
  const uid = String(data.uid || "").toLowerCase();
  const [users, licenses] = await Promise.all([readState(env, "users", {}), readState(env, "licenses", {})]);
  const user = users[uid];
  if (!user || !validSession(user, data.token)) return json({ success: false, error: "Gecersiz oturum" });
  const row = licenses[user.license_id];
  if (!row) return json({ success: false, error: "Lisans bulunamadi" });
  const tgToken = String(data.telegram_token || "").trim();
  const chatId = String(data.telegram_chat_id || "").trim();
  if (!tgToken || !chatId) return json({ success: false, error: "Eksik Telegram bilgisi" });
  const probe = await fetch(`https://api.telegram.org/bot${tgToken}/getMe`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
  const result = await probe.json().catch(() => ({}));
  if (!probe.ok || !result.ok) return json({ success: false, error: "Telegram bot token gecersiz" });
  row.telegram_token = tgToken;
  row.telegram_chat_id = chatId;
  row.telegram_connected_at = nowIso();
  licenses[user.license_id] = row;
  await writeState(env, "licenses", licenses);
  return json({ success: true, bot: result.result || {} });
}

async function clientCommand(request, env) {
  const data = await bodyJson(request);
  const uid = String(data.uid || "").toLowerCase();
  const users = await readState(env, "users", {});
  if (!users[uid] || !validSession(users[uid], data.token)) return json({ success: false, error: "Gecersiz oturum" });
  const queue = await readState(env, "client_commands", []);
  const command = queue.shift() || null;
  if (command) await writeState(env, "client_commands", queue);
  return json({ success: true, command });
}

async function bootstrapCheck(request, env) {
  const auth = await botIdentity(request, env);
  if (auth.error) return auth.error;
  return json({ success: true, uid: auth.uid, client_id: auth.clientId });
}

async function noticeNext(request, env) {
  const data = await bodyJson(request);
  const uid = String(data.uid || "").toLowerCase();
  const [users, licenses, globalNotice] = await Promise.all([
    readState(env, "users", {}), readState(env, "licenses", {}), readState(env, "notice", {}),
  ]);
  const user = users[uid];
  if (!user || !validSession(user, data.token)) return json({ success: false, error: "Gecersiz oturum" });
  const row = licenses[user.license_id] || {};
  const personal = row.personal_notice || user.personal_notice || {};
  const seenPersonal = user.seen_personal_notice_ids || [];
  const seenGlobal = user.seen_notice_ids || [];
  let notice = null;
  if (personal.id && personal.text && !seenPersonal.includes(personal.id)) notice = personal;
  else if (globalNotice.id && globalNotice.text && !seenGlobal.includes(globalNotice.id)) notice = globalNotice;
  return json({ success: true, notice });
}

async function noticeAck(request, env) {
  const data = await bodyJson(request);
  const uid = String(data.uid || "").toLowerCase();
  const users = await readState(env, "users", {});
  const user = users[uid];
  if (!user || !validSession(user, data.token)) return json({ success: false, error: "Gecersiz oturum" });
  const id = String(data.notice_id || "");
  user.seen_notice_ids = [...new Set([...(user.seen_notice_ids || []), id])];
  user.seen_personal_notice_ids = [...new Set([...(user.seen_personal_notice_ids || []), id])];
  user.personal_notice = {};
  users[uid] = user;
  await writeState(env, "users", users);
  return json({ success: true });
}

async function telegramScreenshot(request, env) {
  const data = await bodyJson(request);
  const uid = String(data.uid || "").toLowerCase();
  const [users, licenses] = await Promise.all([readState(env, "users", {}), readState(env, "licenses", {})]);
  const user = users[uid];
  const row = licenses[user?.license_id || ""];
  if (!user || !validSession(user, data.token) || !row) return json({ success: false, error: "Gecersiz oturum" });
  if (!row.telegram_token || !row.telegram_chat_id) return json({ success: false, error: "Telegram bagli degil" });
  const match = String(data.image || "").match(/^data:image\/(?:png|jpeg);base64,(.+)$/);
  if (!match) return json({ success: false, error: "Ekran verisi gecersiz" });
  const raw = Uint8Array.from(atob(match[1]), (c) => c.charCodeAt(0));
  const form = new FormData();
  form.set("chat_id", String(row.telegram_chat_id));
  form.set("caption", "Roller VIP ekran goruntusu");
  form.set("photo", new Blob([raw], { type: "image/png" }), "roller_vip.png");
  const sent = await fetch(`https://api.telegram.org/bot${row.telegram_token}/sendPhoto`, { method: "POST", body: form });
  const result = await sent.json().catch(() => ({}));
  return sent.ok && result.ok ? json({ success: true }) : json({ success: false, error: "Telegram ekran gonderimi basarisiz" });
}

async function adminRoute(request, env, path) {
  if (!isAdmin(request, env)) return json({ success: false, error: "Yetkisiz" }, 401);
  const data = request.method === "POST" ? await bodyJson(request) : {};
  if (path === "/admin/licenses") return json({ success: true, licenses: await readState(env, "licenses", {}) });
  if (path === "/admin/users") return json({ success: true, users: await readState(env, "users", {}) });
  if (path === "/admin/sync-all") {
    const writes = [
      writeState(env, "licenses", data.licenses || {}), writeState(env, "users", data.users || {}),
      writeState(env, "games", data.games || {}), writeState(env, "quick_links", normalizeLinks(data.quick_links || {})),
    ];
    if (data.notice && typeof data.notice === "object") writes.push(writeState(env, "notice", data.notice));
    if (typeof data.bot_content === "string" && data.bot_content.trim()) writes.push(writeState(env, "bot", data.bot_content));
    if (typeof data.bot_android_content === "string" && data.bot_android_content.trim()) writes.push(writeState(env, "bot_android", data.bot_android_content));
    await Promise.all(writes);
    return json({ success: true, licenses_count: Object.keys(data.licenses || {}).length, users_count: Object.keys(data.users || {}).length });
  }
  if (path === "/admin/server-target") {
    const active = cleanUrl(data.active_server_url);
    if (!active) return json({ success: false, error: "Gecersiz sunucu adresi" }, 400);
    await writeState(env, "server_target", { active_server_url: active, updated_at: nowIso() });
    return json({ success: true, active_server_url: active });
  }
  if (path === "/admin/license/create") {
    const licenses = await readState(env, "licenses", {});
    const id = String(data.license_id || "");
    if (!id) return json({ success: false, error: "Lisans id yok" });
    licenses[id] = { ...data, license_id: id, active: true, status: "active", uid: null, last_heartbeat: null };
    await writeState(env, "licenses", licenses);
    return json({ success: true, license: licenses[id] });
  }
  if (["/admin/license/state", "/admin/license/uid-mode"].includes(path)) {
    const licenses = await readState(env, "licenses", {});
    const row = licenses[String(data.license_id || "")];
    if (!row) return json({ success: false, error: "Lisans bulunamadi" });
    if (path.endsWith("state")) { row.active = Boolean(data.active); row.status = row.active ? "active" : "inactive"; }
    else row.allow_uid_change = Boolean(data.allow_uid_change);
    licenses[data.license_id] = row;
    await writeState(env, "licenses", licenses);
    return json({ success: true, license: row });
  }
  if (path === "/admin/license/delete") {
    const [licenses, users, revoked] = await Promise.all([
      readState(env, "licenses", {}), readState(env, "users", {}), readState(env, "revoked_licenses", []),
    ]);
    const id = String(data.license_id || "");
    const row = licenses[id];
    if (!row) return json({ success: false, error: "Lisans bulunamadi" });
    delete licenses[id];
    if (row.uid) delete users[String(row.uid).toLowerCase()];
    revoked.push({ license_id: id, encrypted_license: row.encrypted_license || "", client_id: row.client_id || "", script_hash: row.script_hash || "", deleted_at: nowIso() });
    await Promise.all([writeState(env, "licenses", licenses), writeState(env, "users", users), writeState(env, "revoked_licenses", revoked)]);
    return json({ success: true });
  }
  if (path === "/admin/bot") {
    const variant = String(data.variant || new URL(request.url).searchParams.get("variant") || "desktop") === "android" ? "bot_android" : "bot";
    if (request.method === "GET") {
      const content = await readState(env, variant, "");
      return json({ success: true, variant, bot_size: String(content || "").length });
    }
    if (!String(data.content || "").trim()) return json({ success: false, error: "Bot icerigi bos" });
    await writeState(env, variant, String(data.content));
    return json({ success: true, variant });
  }
  if (path === "/admin/games") {
    if (request.method === "GET") return json({ success: true, games: await readState(env, "games", {}) });
    await writeState(env, "games", data.games || {});
    return json({ success: true, count: Object.keys(data.games || {}).length });
  }
  if (path === "/admin/notice") {
    const notice = { id: String(Date.now()), text: String(data.text || ""), created_at: nowIso(), links: data.links || {} };
    await writeState(env, "notice", notice);
    return json({ success: true, notice });
  }
  if (path === "/admin/notice/user") {
    const [licenses, users] = await Promise.all([readState(env, "licenses", {}), readState(env, "users", {})]);
    let id = String(data.license_id || "");
    if (!id && data.uid) id = String(users[String(data.uid).toLowerCase()]?.license_id || "");
    const row = licenses[id];
    if (!row) return json({ success: false, error: "Lisans bulunamadi" });
    const notice = { id: `${Date.now()}_${crypto.randomUUID().slice(0, 6)}`, text: String(data.text || ""), created_at: nowIso(), scope: "personal", links: data.links || {} };
    row.personal_notice = notice; row.message_text = notice.text; row.message_status = "Gonderildi"; row.message_id = notice.id;
    licenses[id] = row;
    await writeState(env, "licenses", licenses);
    return json({ success: true, notice });
  }
  if (path === "/admin/client-command" || path === "/admin/bot-command") {
    const key = path.includes("client") ? "client_commands" : "bot_commands";
    const queue = await readState(env, key, []);
    queue.push({ command: String(data.command || ""), time: nowIso(), source: "admin" });
    await writeState(env, key, queue.slice(-100));
    return json({ success: true });
  }
  if (path === "/admin/clear-all") {
    const licenses = await readState(env, "licenses", {});
    const revoked = await readState(env, "revoked_licenses", []);
    for (const [id, row] of Object.entries(licenses)) revoked.push({ license_id: id, encrypted_license: row.encrypted_license || "", client_id: row.client_id || "", deleted_at: nowIso(), reason: "admin_clear_all" });
    const writes = [writeState(env, "licenses", {}), writeState(env, "users", {}), writeState(env, "revoked_licenses", revoked), writeState(env, "notice", {})];
    if (!data.keep_games) writes.push(writeState(env, "games", {}));
    if (!data.keep_links) writes.push(writeState(env, "quick_links", {}));
    if (!data.keep_bots) writes.push(writeState(env, "bot", ""), writeState(env, "bot_android", ""));
    await Promise.all(writes);
    return json({ success: true });
  }
  if (path === "/admin/storage-status") {
    const rows = await env.DB.prepare("SELECT key, length(value) AS size, updated_at FROM app_state ORDER BY updated_at DESC LIMIT 20").all();
    return json({ success: true, cloudflare_d1: { enabled: true, ok: true, details: rows.results || [] } });
  }
  return json({ success: false, error: "Admin route bulunamadi" }, 404);
}

async function route(request, env) {
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
  const url = new URL(request.url);
  const path = url.pathname;
  const origin = url.origin;
  if (path === "/" || path === "/api/health") return json({ success: true, service: "server-local-cloudflare", status: "ok", database: Boolean(env.DB), time: nowIso() });
  if (!env.DB) return json({ success: false, error: "Cloudflare D1 DB binding eksik" }, 503);
  if (path.startsWith("/admin/")) return adminRoute(request, env, path);

  const redirect = await activeRedirect(request, env, origin);
  if (redirect) return redirect;
  if (path === "/api/client-config") {
    const target = await readState(env, "server_target", {});
    const active = cleanUrl(target.active_server_url) || origin;
    const candidates = [active, origin, ...String(env.CLIENT_SERVER_URLS || "").split(/[\s,;]+/)];
    const serverUrls = [...new Set(candidates.map(cleanUrl).filter(Boolean))];
    return json({ success: true, data: { server_urls: serverUrls, active_server_url: active, config_version: "cf-1" } });
  }
  if (path === "/api/public-links") return json({ success: true, quick_links: normalizeLinks(await readState(env, "quick_links", {})) });
  if (path === "/api/auth" && request.method === "POST") return authenticate(request, env, origin);
  if (path === "/api/heartbeat" && request.method === "POST") return heartbeat(request, env);
  if (path === "/api/telegram/register" && request.method === "POST") return registerTelegram(request, env);
  if (path === "/api/client/command" && request.method === "POST") return clientCommand(request, env);
  if (path === "/api/bot/bootstrap-check" && request.method === "POST") return bootstrapCheck(request, env);
  if (path === "/api/notice/next" && request.method === "POST") return noticeNext(request, env);
  if (path === "/api/notice/ack" && request.method === "POST") return noticeAck(request, env);
  if (path === "/api/telegram/screenshot" && request.method === "POST") return telegramScreenshot(request, env);
  if (path === "/games") {
    const auth = await botIdentity(request, env); if (auth.error) return auth.error;
    return json(await readState(env, "games", {}));
  }
  if (path === "/user_id") {
    if (request.method === "POST") {
      const data = await bodyJson(request); const uid = String(data.user_id || data.uid || "").toLowerCase();
      if (!/^[a-f0-9]{24}$/i.test(uid)) return json({ success: false, error: "Gecersiz user id" });
      await writeState(env, "latest_uid", uid); return json({ success: true, user_id: uid });
    }
    return json({ success: true, user_id: await readState(env, "latest_uid", "") });
  }
  if (path === "/api/miner/bootstrap") {
    const auth = await botIdentity(request, env); if (auth.error) return auth.error;
    const brain = cleanUrl(env.MINER_BRAIN_URL);
    return json({ success: true, enabled: Boolean(brain), mode: brain ? "remote-brain" : "cloudflare-auth-only", uid: auth.uid, routes: brain ? { arrange_plan: `${origin}/api/miner/arrange-plan` } : {} });
  }
  if (path === "/api/miner/arrange-plan" && request.method === "POST") {
    const auth = await botIdentity(request, env); if (auth.error) return auth.error;
    const brain = cleanUrl(env.MINER_BRAIN_URL);
    if (!brain) return json({ success: false, error: "Miner plan servisi yapilandirilmadi" }, 503);
    return fetch(`${brain}/api/miner/arrange-plan`, { method: "POST", headers: request.headers, body: await request.text() });
  }
  return json({ success: false, error: "Not found" }, 404);
}

export default {
  async fetch(request, env) {
    try { return await route(request, env); }
    catch (error) { return json({ success: false, error: String(error?.message || error) }, 500); }
  },
};
