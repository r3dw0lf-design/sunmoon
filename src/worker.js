/* Sun & Moon - account API as a Cloudflare Worker (served at /api/*, static files come from ./public).
   ONE shared list of accounts for everyone, stored in Cloudflare D1 (one SQLite table, strongly consistent).
   - A username is claimed with a "write only if new" call, so two people can never both get it,
     even if they click at the same instant from different countries.
   - Passwords + recovery codes are stored only as salted scrypt hashes.
   - Logins are HttpOnly cookies backed by server-side sessions.
   Variables (Cloudflare > Workers & Pages > your project > Settings > Variables and Secrets):
     ADMIN_PASSWORD     optional: a different password for the ADMIN login (replaces the built-in one)
     SINGLE_SESSION=1   logging in on a new device logs the old one out */

let DB;                                                       // the D1 database (bound as DB in wrangler.toml)
/* A tiny key-value layer on D1 (table kv: k, v, ver). It offers the same calls the old Netlify Blobs store did, including
   "write only if new" and "write only if unchanged" (ver is the etag), so every route below works as it was.
   Reads and deletes issued in the same tick are merged into ONE query, which keeps a request under Cloudflare's subrequest limit. */
const gq = [], dq = [];
const qGet = k => new Promise((res, rej) => { if (!gq.length) queueMicrotask(flushGets); gq.push({ k, res, rej }); });
const qDel = k => new Promise((res, rej) => { if (!dq.length) queueMicrotask(flushDels); dq.push({ k, res, rej }); });
async function flushGets() {
  const q = gq.splice(0), keys = [...new Set(q.map(x => x.k))], rows = new Map();
  try {
    for (let i = 0; i < keys.length; i += 90) { const p = keys.slice(i, i + 90), r = await DB.prepare(`SELECT k, v, ver FROM kv WHERE k IN (${p.map(() => "?").join(",")})`).bind(...p).all(); for (const x of r.results) rows.set(x.k, x); }
    q.forEach(x => x.res(rows.get(x.k) || null));
  } catch (e) { q.forEach(x => x.rej(e)); }
}
async function flushDels() {
  const q = dq.splice(0);
  try { const st = DB.prepare("DELETE FROM kv WHERE k = ?"); for (let i = 0; i < q.length; i += 90) await DB.batch(q.slice(i, i + 90).map(x => st.bind(x.k))); q.forEach(x => x.res()); }
  catch (e) { q.forEach(x => x.rej(e)); }
}
const d1Store = () => ({
  async get(k) { const r = await qGet(k); return r ? JSON.parse(r.v) : null; },
  async getWithMetadata(k) { const r = await qGet(k); return r ? { data: JSON.parse(r.v), etag: String(r.ver) } : null; },
  async setJSON(k, val, o = {}) {
    const v = JSON.stringify(val); let r;
    if (o.onlyIfNew) r = await DB.prepare("INSERT INTO kv (k, v, ver) VALUES (?, ?, 1) ON CONFLICT(k) DO NOTHING").bind(k, v).run();
    else if (o.onlyIfMatch !== undefined) r = await DB.prepare("UPDATE kv SET v = ?, ver = ver + 1 WHERE k = ? AND ver = ?").bind(v, k, Number(o.onlyIfMatch)).run();
    else r = await DB.prepare("INSERT INTO kv (k, v, ver) VALUES (?, ?, 1) ON CONFLICT(k) DO UPDATE SET v = excluded.v, ver = kv.ver + 1").bind(k, v).run();
    return { modified: r.meta.changes > 0 };
  },
  delete: k => qDel(k),
  async list({ prefix = "" } = {}) { const r = await DB.prepare("SELECT k FROM kv WHERE k >= ? AND k < ? ORDER BY k").bind(prefix, prefix + "\uffff").all(); return { blobs: r.results.map(x => ({ key: x.k })) }; },
});
import crypto from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(crypto.scrypt);
const USER_RE = /^[a-z0-9_.-]{3,20}$/;
const SESSION_MS = 365 * 24 * 3600 * 1000;
let SINGLE_SESSION = false;
let ADMIN_PASSWORD = "";                                     // optional override (a Cloudflare variable)
/* The built-in ADMIN password is kept here only as a salted scrypt hash, never as readable text, so even if someone
   downloads this file they cannot read it. Log in as ADMIN with your password; to change it later, set ADMIN_PASSWORD. */
const ADMIN_BUILTIN = { salt: "H+Z8r2xCffAVILM54j82Mg==", hash: "0no3ZX30M6lWzMiCCWYGBTslzv3CybNQASqcJCK4zhc=" };
const ADMIN_MS = 8 * 3600 * 1000;                          // an admin login lasts 8 hours
const store = d1Store;

/* ---------------- helpers ---------------- */
const sha = s => crypto.createHash("sha256").update(s).digest("hex");
async function makeHash(secret) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(String(secret).normalize("NFKC"), salt, 32);
  return { salt: salt.toString("base64"), hash: key.toString("base64") };
}
async function checkHash(secret, rec) {
  if (!rec) return false;
  const key = await scrypt(String(secret).normalize("NFKC"), Buffer.from(rec.salt, "base64"), 32);
  return crypto.timingSafeEqual(key, Buffer.from(rec.hash, "base64"));
}
const normCode = c => String(c || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
function newRecoveryCode() {
  const A = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789", b = crypto.randomBytes(16);
  let s = ""; for (let i = 0; i < 16; i++) s += A[b[i] % A.length];
  return s.match(/.{4}/g).join("-");
}
function cleanSettings(s) {
  s = s && typeof s === "object" ? s : {};
  const txt = (v, max, nl) => typeof v === "string" ? v.replace(nl ? /[\u0000-\u0009\u000B\u000C\u000E-\u001F\u007F]/g : /[\u0000-\u001F\u007F]/g, "").slice(0, max) : "";
  const num = (v, lo, hi, d) => typeof v === "number" && isFinite(v) ? Math.min(hi, Math.max(lo, v)) : d;
  return { sun: txt(s.sun, 12), moon: txt(s.moon, 12), since: typeof s.since === "string" && /^\d{4}-\d{2}-\d{2}$/.test(s.since) ? s.since : "",
    letter: txt(s.letter, 600, true), palette: Math.round(num(s.palette, 0, 4, 0)), crt: typeof s.crt === "boolean" ? s.crt : true,
    speed: num(s.speed, 0.2, 4, 1), volume: num(s.volume, 0, 1, 0.8) };
}
const pubUser = (rec, lastLoginAt) => ({ username: rec.username, settings: rec.settings, loginCount: rec.loginCount, pair: rec.pair || null,
  lastLoginAt: lastLoginAt === undefined ? rec.lastLoginAt : lastLoginAt });
const fail = (status, code, extra) => Object.assign(new Error(code), { status, code, extra });

/* read-change-write on a user record, retried if someone else changed it in between (compare-and-swap on the etag) */
async function mutate(username, fn) {
  const st = store();
  for (let i = 0; i < 5; i++) {
    const cur = await st.getWithMetadata("u/" + username, { type: "json", consistency: "strong" });
    if (!cur) throw fail(404, "NO_ACCOUNT");
    const next = await fn(structuredClone(cur.data));
    const r = await st.setJSON("u/" + username, next, { onlyIfMatch: cur.etag });
    if (r.modified) return next;
  }
  throw fail(503, "SERVER");
}
const getUser = username => store().get("u/" + username, { type: "json", consistency: "strong" });

/* ---- letters: stored as m/<recipient>/<timestamp>-<random>, so each inbox is one prefix ---- */
const ID_RE = /^\d{13}-[0-9a-f]{8}$/;
const INBOX_MAX = 100, OUTBOX_MAX = 100;
const SYS_FROM = "Sun & Moon OS";
const CHANGELOG = [   // add one entry per update (v goes up by 1); everyone gets the new ones in their inbox
  { v: 1, at: Date.UTC(2026, 10, 1, 12, 0, 0), text: "UPDATE LOG #1 - Sun & Moon OS\nReleased 1 Nov 2026\n\nNEW\n- Faster sync: mini game moves refresh about every 0.3 seconds, letters and invites about every 1.5 seconds.\n- Movable desktop icons: drag them anywhere (on a phone, hold first). Hold or right-click an icon to rename it, resize it, hide its label, or reset the layout.\n- Settings > Security: change your password and make a new recovery code.\n- Six scenic wallpapers: Alpine, City, Desert, Aurora, Sakura and Meadow, each in light and dark.\n- Window styles: Liquid Glass, 2000s Aero and 90s Retro, each with its own accent colours (Settings > Personalisation).\n- Every future update will arrive in your inbox as a log like this one.\n\nEnjoy! - Sun & Moon OS" },
];
async function deliverUpdates(rec) {                              // update-log letters: each user gets every entry they haven't had yet (ids are fixed, so it can never double up)
  const have = rec.updVer || 0, latest = CHANGELOG[CHANGELOG.length - 1].v;
  if (have >= latest) return;
  const st = store(), { blobs } = await st.list({ prefix: `m/${rec.username}/` });
  if (blobs.length >= INBOX_MAX) return;                       // inbox full: try again once there's room
  for (const e of CHANGELOG) if (e.v > have) await st.setJSON(`m/${rec.username}/${e.at}-${e.v.toString(16).padStart(8, "0")}`, { from: SYS_FROM, type: "update", text: e.text, at: e.at, read: false, sys: true }, { onlyIfNew: true });
  await mutate(rec.username, r => { r.updVer = Math.max(r.updVer || 0, latest); return r; });
}
const snip = t => { t = String(t || "").replace(/\s+/g, " ").trim(); return t.length > 70 ? t.slice(0, 67) + "..." : t; };
const cleanLetterText = v => String(v || "").replace(/[\u2665\u2764]\uFE0F?/g, " <3 ").replace(/[\u2018\u2019]/g, "'").replace(/[\u201C\u201D]/g, '"')
  .replace(/[\u2013\u2014]/g, "-").replace(/\u2026/g, "...").replace(/[^\x20-\x7E\n]/g, "").toUpperCase().slice(0, 600).trim();
const sendHits = new Map();                                   // best-effort: 10 letters a minute per sender
function sendLimited(user) {
  const t = Date.now(), r = sendHits.get(user) || { n: 0, reset: t + 60000 };
  if (t > r.reset) { r.n = 0; r.reset = t + 60000; }
  r.n++; sendHits.set(user, r);
  if (sendHits.size > 5000) sendHits.clear();
  return r.n > 10;
}
async function needUser(req) { const s = await sessionUser(req); if (!s) throw fail(401, "UNAUTH"); return s; }
async function updateLetter(me, id, fn) {
  if (!ID_RE.test(String(id))) throw fail(400, "SERVER");
  const st = store(), key = `m/${me}/${id}`;                  // "me" comes from the login, so nobody can touch someone else's mail
  for (let i = 0; i < 3; i++) {
    const cur = await st.getWithMetadata(key, { type: "json", consistency: "strong" });
    if (!cur) throw fail(404, "SERVER");
    const r = await st.setJSON(key, fn(cur.data), { onlyIfMatch: cur.etag });
    if (r.modified) return;
  }
}

/* the sender keeps their own copy at o/<sender>/<same id>, so "Sent" can show whether each letter has been opened */
async function patchSent(sender, id, patch) {
  const st = store(), key = `o/${sender}/${id}`;
  for (let i = 0; i < 3; i++) {
    const cur = await st.getWithMetadata(key, { type: "json", consistency: "strong" });
    if (!cur) return;                                          // older letters (sent before this feature) have no sent copy
    const r = await st.setJSON(key, { ...cur.data, ...patch }, { onlyIfMatch: cur.etag });
    if (r.modified) return;
  }
}
const markSent = (sender, id, openedAt) => patchSent(sender, id, { read: true, openedAt });
/* a short notice for someone (letter opened, pair request answered, ...). Every notice has a kind so the page can word it clearly. */
async function notify(user, obj) {
  const st = store(), { blobs } = await st.list({ prefix: `n/${user}/` });
  if (blobs.length < 50) await st.setJSON(`n/${user}/${Date.now()}-${crypto.randomBytes(4).toString("hex")}`, { at: Date.now(), ...obj }, { onlyIfNew: true });
}
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
function checkDate(v) {
  v = String(v || "");
  const t = Date.parse(v + "T00:00:00Z");
  if (!DATE_RE.test(v) || !isFinite(t) || new Date(t).toISOString().slice(0, 10) !== v || v < "1950-01-01" || t > Date.now() + 2 * 86400000) throw fail(400, "BAD_DATE");
  return v;
}

/* best-effort per-IP throttle (per warm function instance; the per-account lockout below is the real guard) */
const ipHits = new Map();
function ipLimited(ip) {
  const t = Date.now(), r = ipHits.get(ip) || { n: 0, reset: t + 60000 };
  if (t > r.reset) { r.n = 0; r.reset = t + 60000; }
  r.n++; ipHits.set(ip, r);
  if (ipHits.size > 5000) ipHits.clear();
  return r.n > 40;
}

/* ---------------- sessions ---------------- */
function readCookie(req, name) {
  const m = (req.headers.get("cookie") || "").split(/;\s*/).find(c => c.startsWith(name + "="));
  return m ? decodeURIComponent(m.slice(name.length + 1)) : "";
}
async function sessionUser(req) {
  const tok = readCookie(req, "sm_session");
  if (!/^[0-9a-f]{64}$/.test(tok)) return null;
  const s = await store().get("s/" + sha(tok), { type: "json", consistency: "strong" });
  if (!s || s.exp < Date.now()) return null;
  const rec = await getUser(s.username);
  if (!rec || rec.epoch !== s.epoch || (rec.uid || "") !== (s.uid || "")) return null;   // epoch changes on password reset / SINGLE_SESSION; uid changes if the name is re-created
  return { rec, hash: sha(tok) };
}
async function startSession(res, req, rec) {
  const tok = crypto.randomBytes(32).toString("hex");
  await store().setJSON("s/" + sha(tok), { username: rec.username, epoch: rec.epoch, uid: rec.uid, exp: Date.now() + SESSION_MS });
  const secure = new URL(req.url).protocol === "https:" || req.headers.get("x-forwarded-proto") === "https";
  res.headers.append("Set-Cookie", `sm_session=${tok}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_MS / 1000}${secure ? "; Secure" : ""}`);
}

/* ---------------- admin ---------------- */
const digest = v => crypto.createHash("sha256").update(String(v)).digest();
const secureFlag = req => (new URL(req.url).protocol === "https:" || req.headers.get("x-forwarded-proto") === "https") ? "; Secure" : "";
async function adminSession(req) {
  const tok = readCookie(req, "sm_admin");
  if (!/^[0-9a-f]{64}$/.test(tok)) return null;
  const a = await store().get("a/" + sha(tok), { type: "json", consistency: "strong" });
  return a && a.exp > Date.now() ? { hash: sha(tok) } : null;
}
async function needAdmin(req) { const a = await adminSession(req); if (!a) throw fail(401, "UNAUTH"); return a; }
async function adminLogin(req, res, b) {
  const st = store();
  const f = (await st.get("meta/adminfails", { type: "json", consistency: "strong" })) || { n: 0, until: 0 };
  if (f.until > Date.now()) throw fail(429, "TOO_MANY", { retry: Math.ceil((f.until - Date.now()) / 1000) });
  const okPw = ADMIN_PASSWORD ? crypto.timingSafeEqual(digest(b.password || ""), digest(ADMIN_PASSWORD)) : await checkHash(String(b.password || ""), ADMIN_BUILTIN);
  if (!okPw) {
    f.n++; if (f.n >= 5) f.until = Date.now() + Math.min(900000, 30000 * 2 ** (f.n - 5));   // 5 wrong tries: pause 30s, doubling, up to 15 min
    await st.setJSON("meta/adminfails", f);
    throw fail(401, "BAD_PASSWORD");
  }
  if (f.n) await st.setJSON("meta/adminfails", { n: 0, until: 0 });
  const tok = crypto.randomBytes(32).toString("hex");
  await st.setJSON("a/" + sha(tok), { exp: Date.now() + ADMIN_MS });
  res.headers.append("Set-Cookie", `sm_admin=${tok}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${ADMIN_MS / 1000}${secureFlag(req)}`);
  return { admin: true };
}

/* ---------------- routes ---------------- */
function checkUsername(u) {
  u = String(u || "").trim().toLowerCase();
  if (!USER_RE.test(u)) throw fail(400, "BAD_USERNAME");
  return u;
}
function lockCheck(rec) {
  const t = Date.now();
  if (rec.fails && rec.fails.until > t) throw fail(429, "TOO_MANY", { retry: Math.ceil((rec.fails.until - t) / 1000) });
}
async function noteFail(username, code) {
  await mutate(username, rec => {
    const f = rec.fails || { n: 0, until: 0 }; f.n++;
    if (f.n >= 5) f.until = Date.now() + 30000;          // 5 wrong tries = 30 second pause
    rec.fails = f; return rec;
  });
  throw fail(401, code);
}


/* ---------------- mini games + online status (paired people only) ---------------- */
const GAMES = { ttt: "TIC-TAC-TOE", c4: "CONNECT 4" };
const ONLINE_MS = 40000;                                       // a page pings every ~12s, so 40s of silence = offline
const pairKey = (a, b) => [a, b].sort().join("~");
async function pairCtx(req) {
  const rec = (await needUser(req)).rec;
  if (!rec.pair) throw fail(409, "NOT_PAIRED");
  return { me: rec.username, other: rec.pair.with, key: pairKey(rec.username, rec.pair.with) };
}
const getGame = key => store().getWithMetadata(`g/${key}`, { type: "json", consistency: "strong" });
async function casGame(key, fn) {                              // change the game only if nobody else changed it in between
  const st = store();
  for (let i = 0; i < 5; i++) {
    const cur = await getGame(key);
    if (!cur) throw fail(404, "NO_GAME");
    const next = fn(structuredClone(cur.data));
    next.ver = (cur.data.ver || 0) + 1; next.updatedAt = Date.now();
    const r = await st.setJSON(`g/${key}`, next, { onlyIfMatch: cur.etag });
    if (r.modified) return next;
  }
  throw fail(503, "SERVER");
}
const chatHits = new Map();                                    // best-effort: 15 chat messages per 10 seconds
function chatLimited(user) {
  const t = Date.now(), r = chatHits.get(user) || { n: 0, reset: t + 10000 };
  if (t > r.reset) { r.n = 0; r.reset = t + 10000; }
  r.n++; chatHits.set(user, r); if (chatHits.size > 5000) chatHits.clear();
  return r.n > 15;
}
const TTT_LINES = [[0,1,2],[3,4,5],[6,7,8],[0,3,6],[1,4,7],[2,5,8],[0,4,8],[2,4,6]];
function tttCheck(b) {
  for (const l of TTT_LINES) if (b[l[0]] !== null && b[l[0]] === b[l[1]] && b[l[1]] === b[l[2]]) return { w: b[l[0]], line: l };
  return b.every(c => c !== null) ? { w: -1, line: [] } : null;
}
function c4Check(b) {                                          // 6 rows x 7 columns, row 0 is the top
  for (let r = 0; r < 6; r++) for (let c = 0; c < 7; c++) {
    const v = b[r * 7 + c]; if (v === null) continue;
    for (const [dr, dc] of [[0, 1], [1, 0], [1, 1], [1, -1]]) {
      const line = [];
      for (let k = 0; k < 4; k++) { const rr = r + dr * k, cc = c + dc * k; if (rr < 0 || rr > 5 || cc < 0 || cc > 6 || b[rr * 7 + cc] !== v) break; line.push(rr * 7 + cc); }
      if (line.length === 4) return { w: v, line };
    }
  }
  return b.every(c => c !== null) ? { w: -1, line: [] } : null;
}
const emptyBoard = type => Array(type === "c4" ? 42 : 9).fill(null);
function carryScore(prev, a, b) { const sc = prev && prev.score || {}; return { [a]: sc[a] || 0, [b]: sc[b] || 0, draws: sc.draws || 0 }; }

const routes = {
  async me(req) {
    if (await adminSession(req)) return { admin: true, user: null, hasUsers: true };
    const s = await sessionUser(req);
    return { user: s ? pubUser(s.rec) : null, hasUsers: true };
  },

  async signup(req, res, b) {
    const username = checkUsername(b.username), password = String(b.password || "");
    if (password.length < 6 || password.length > 100) throw fail(400, "WEAK_PASSWORD");
    if (username === "admin" || await getUser(username)) throw fail(409, "USERNAME_TAKEN");   // "admin" is reserved for the admin panel
    const recoveryCode = newRecoveryCode(), pw = await makeHash(password), rc = await makeHash(normCode(recoveryCode));
    const now = Date.now();
    const rec = { username, pw, rc, settings: cleanSettings(b.settings), createdAt: now, lastLoginAt: now, loginCount: 1, updVer: CHANGELOG[CHANGELOG.length - 1].v, epoch: 1, uid: crypto.randomBytes(8).toString("hex"), fails: { n: 0, until: 0 } };
    const r = await store().setJSON("u/" + username, rec, { onlyIfNew: true });   // the one atomic step that makes the name yours alone
    if (!r.modified) throw fail(409, "USERNAME_TAKEN");
    await startSession(res, req, rec);
    return { user: pubUser(rec, null), recoveryCode };
  },

  async login(req, res, b) {
    if (String(b.username || "").trim() === "ADMIN") return adminLogin(req, res, b);   // exactly ADMIN in capitals; accounts are always lowercase
    const username = checkUsername(b.username), password = String(b.password || "");
    const rec = await getUser(username);
    if (!rec) throw fail(404, "NO_ACCOUNT");
    lockCheck(rec);
    if (!(await checkHash(password, rec.pw))) await noteFail(username, "BAD_PASSWORD");
    let prev;
    const upd = await mutate(username, r => {
      prev = r.lastLoginAt;
      r.fails = { n: 0, until: 0 }; r.lastLoginAt = Date.now(); r.loginCount = (r.loginCount || 0) + 1;
      if (SINGLE_SESSION) r.epoch = (r.epoch || 1) + 1;   // invalidates every other device's login
      return r;
    });
    await startSession(res, req, upd);
    return { user: pubUser(upd, prev) };
  },

  async recover(req, res, b) {
    const username = checkUsername(b.username), code = normCode(b.code), newPassword = String(b.password || "");
    if (newPassword.length < 6 || newPassword.length > 100) throw fail(400, "WEAK_PASSWORD");
    const rec = await getUser(username);
    if (!rec) throw fail(404, "NO_ACCOUNT");
    lockCheck(rec);
    if (!(code.length === 16 && await checkHash(code, rec.rc))) await noteFail(username, "BAD_RECOVERY");
    const recoveryCode = newRecoveryCode(), pw = await makeHash(newPassword), rc = await makeHash(normCode(recoveryCode));
    let prev;
    const upd = await mutate(username, r => {
      prev = r.lastLoginAt;
      r.pw = pw; r.rc = rc; r.fails = { n: 0, until: 0 };  // the old recovery code stops working
      r.epoch = (r.epoch || 1) + 1;                        // a reset signs out every device
      r.lastLoginAt = Date.now(); r.loginCount = (r.loginCount || 0) + 1;
      return r;
    });
    await startSession(res, req, upd);
    return { user: pubUser(upd, prev), recoveryCode };
  },

  /* ---- security tab: change password / make a new recovery code (both need the current password) ---- */
  async change_password(req, res, b) {
    const username = (await needUser(req)).rec.username, np = String(b.password || "");
    if (np.length < 6 || np.length > 100) throw fail(400, "WEAK_PASSWORD");
    const rec = await getUser(username);
    if (!rec) throw fail(404, "NO_ACCOUNT");
    lockCheck(rec);
    if (!(await checkHash(String(b.current || ""), rec.pw))) await noteFail(username, "BAD_PASSWORD");
    const pw = await makeHash(np);
    const upd = await mutate(username, r => { r.pw = pw; r.fails = { n: 0, until: 0 }; r.epoch = (r.epoch || 1) + 1; return r; });   // other devices get signed out
    await startSession(res, req, upd);                          // this device stays signed in
    return { ok: true };
  },

  async new_recovery(req, res, b) {
    const username = (await needUser(req)).rec.username;
    const rec = await getUser(username);
    if (!rec) throw fail(404, "NO_ACCOUNT");
    lockCheck(rec);
    if (!(await checkHash(String(b.current || ""), rec.pw))) await noteFail(username, "BAD_PASSWORD");
    const recoveryCode = newRecoveryCode(), rc = await makeHash(normCode(recoveryCode));
    await mutate(username, r => { r.rc = rc; r.fails = { n: 0, until: 0 }; return r; });         // the old recovery code stops working
    return { recoveryCode };
  },

  async settings(req, res, b) {
    const s = await sessionUser(req);
    if (!s) throw fail(401, "UNAUTH");
    await mutate(s.rec.username, r => { r.settings = cleanSettings(b.settings); return r; });
    return { ok: true };
  },

  /* every account name, so people can pick who to write to (logged-in users only) */
  async users(req) {
    await needUser(req);
    const { blobs } = await store().list({ prefix: "u/" });
    return { users: blobs.map(b => b.key.slice(2)).sort() };
  },

  async send(req, res, b) {
    const me = (await needUser(req)).rec.username;
    const img = typeof b.img === "string" && b.img.length <= 150000 && /^data:image\/jpeg;base64,[A-Za-z0-9+\/=]{100,}$/.test(b.img) ? b.img : "";
    if (b.img && !img) throw fail(400, "BAD_IMG");
    const to = checkUsername(b.to), text = cleanLetterText(b.text) || (img ? "[PHOTO]" : "");
    if (!text) throw fail(400, "EMPTY");
    if (sendLimited(me)) throw fail(429, "TOO_MANY", { retry: 30 });
    if (!(await getUser(to))) throw fail(404, "NO_USER");
    const st = store();
    const { blobs } = await st.list({ prefix: `m/${to}/` });
    if (blobs.length >= INBOX_MAX) throw fail(409, "INBOX_FULL");
    let re = null;                                             // replying to one specific letter: the server looks it up itself, so it can't be faked
    if (b.replyTo && ID_RE.test(String(b.replyTo))) {
      const orig = await st.get(`m/${me}/${b.replyTo}`, { type: "json", consistency: "strong" });
      if (orig && orig.from === to) re = { id: String(b.replyTo), snip: snip(orig.text) };
    }
    const at = Date.now(), id = at + "-" + crypto.randomBytes(4).toString("hex");
    await st.setJSON(`m/${to}/${id}`, Object.assign({ from: me, text, at, read: false }, re ? { re } : {}, img ? { img } : {}), { onlyIfNew: true });
    try {                                                      // the sender's own copy (never lets the send fail)
      await st.setJSON(`o/${me}/${id}`, Object.assign({ to, text, at, read: false }, re ? { re } : {}, img ? { img } : {}), { onlyIfNew: true });
      const { blobs: ob } = await st.list({ prefix: `o/${me}/` });
      if (ob.length > OUTBOX_MAX) await Promise.all(ob.map(x => x.key).sort().slice(0, ob.length - OUTBOX_MAX).map(k => st.delete(k)));
    } catch (e) { console.error(e); }
    if (re) {                                                  // answering a letter means you read it: mark it quietly (the reply itself is the news)
      try {
        let was = false, when = Date.now();
        await updateLetter(me, re.id, l => { was = !l.read; if (was) l.openedAt = when; l.read = true; return l; });
        if (was) await markSent(to, re.id, when);
      } catch (e) { console.error(e); }
    }
    return { ok: true };
  },

  async inbox(req) {
    const meRec = (await needUser(req)).rec, me = meRec.username, st = store();
    try { await deliverUpdates(meRec); } catch (e) { console.error(e); }
    const { blobs } = await st.list({ prefix: `m/${me}/` });
    const keys = blobs.map(x => x.key).sort().reverse().slice(0, 50);   // newest first
    const items = await Promise.all(keys.map(async k => {
      const v = await st.get(k, { type: "json", consistency: "strong" });
      return v && { id: k.slice(k.lastIndexOf("/") + 1), from: v.from, text: v.text, hasImg: !!v.img, at: v.at, read: !!v.read, re: v.re || null,
        type: v.type || "letter", since: v.since || "", status: v.status || "", role: v.role || "sun", gtype: v.gtype || "", gid: v.gid || "" };
    }));
    const { blobs: nb } = await st.list({ prefix: `n/${me}/` });                      // "they opened your letter" notices for this person
    const notifs = (await Promise.all(nb.map(x => x.key).sort().slice(0, 20).map(async k => {
      const v = await st.get(k, { type: "json", consistency: "strong" });
      return v && { id: k.slice(k.lastIndexOf("/") + 1), by: v.by, at: v.at, sentAt: v.sentAt, kind: v.kind || "opened", snip: v.snip || "" };
    }))).filter(Boolean);
    return { letters: items.filter(Boolean), notifs, pair: meRec.pair || null };
  },

  async read(req, res, b) {
    const me = (await needUser(req)).rec.username;
    let sender = null, sentAt = 0, openedAt = 0, text = "", type = "letter";
    await updateLetter(me, b.id, l => {
      sender = null;                                           // (runs again if the write had to be retried)
      if (!l.read) { sender = l.from; sentAt = l.at; openedAt = Date.now(); text = l.text; type = l.type || "letter"; l.openedAt = openedAt; }
      l.read = true; return l;
    });
    if (sender && type === "letter") {                         // first time a real letter was opened: update their Sent list and leave them a notice
      try { await markSent(sender, b.id, openedAt); } catch (e) { console.error(e); }
      if (sender !== me && await getUser(sender)) await notify(sender, { kind: "opened", by: me, sentAt, sid: b.id, snip: snip(text) });
    }
    return { ok: true };
  },

  async ack(req, res, b) {                                     // the sender's page has shown these notices, so they can go
    const me = (await needUser(req)).rec.username;
    const ids = (Array.isArray(b.ids) ? b.ids : []).slice(0, 50).filter(id => ID_RE.test(String(id)));
    await Promise.all(ids.map(id => store().delete(`n/${me}/${id}`)));
    return { ok: true };
  },

  /* ---- pairing: a request lands in their inbox (and pops up if they're online); accepting links both accounts ---- */
  async pair_request(req, res, b) {
    const meRec = (await needUser(req)).rec, me = meRec.username;
    const to = checkUsername(b.to), since = checkDate(b.since);
    const role = b.role === "moon" ? "moon" : "sun";           // what the person asking wants to be; the other one gets the other role
    if (to === me) throw fail(400, "SELF");
    if (sendLimited(me)) throw fail(429, "TOO_MANY", { retry: 30 });
    const target = await getUser(to);
    if (!target) throw fail(404, "NO_USER");
    if (meRec.pair) throw fail(409, "ALREADY_PAIRED");
    if (target.pair) throw fail(409, "THEY_PAIRED");
    const st = store();
    const { blobs: ob } = await st.list({ prefix: `o/${me}/` });
    const mine = await Promise.all(ob.map(x => st.get(x.key, { type: "json", consistency: "strong" })));
    if (mine.some(v => v && v.type === "pair" && v.to === to && v.status === "pending")) throw fail(409, "ALREADY_SENT");
    const { blobs } = await st.list({ prefix: `m/${to}/` });
    if (blobs.length >= INBOX_MAX) throw fail(409, "INBOX_FULL");
    const at = Date.now(), id = at + "-" + crypto.randomBytes(4).toString("hex");
    await st.setJSON(`m/${to}/${id}`, { from: me, type: "pair", since, role, status: "pending", text: "PAIR REQUEST", at, read: false }, { onlyIfNew: true });
    await st.setJSON(`o/${me}/${id}`, { to, type: "pair", since, role, status: "pending", text: "PAIR REQUEST", at, read: false }, { onlyIfNew: true });
    return { ok: true };
  },

  async pair_answer(req, res, b) {
    const meRec = (await needUser(req)).rec, me = meRec.username, st = store();
    if (!ID_RE.test(String(b.id))) throw fail(400, "SERVER");
    const letter = await st.get(`m/${me}/${b.id}`, { type: "json", consistency: "strong" });
    if (!letter || letter.type !== "pair") throw fail(404, "SERVER");
    if (letter.status !== "pending") return { ok: true, status: letter.status };
    const from = letter.from;
    if (b.accept) {
      const other = await getUser(from);
      if (!other) throw fail(404, "NO_USER");
      if (meRec.pair || other.pair) throw fail(409, "ALREADY_PAIRED");
      const askerIsMoon = letter.role === "moon", since = letter.since;
      const sun = (askerIsMoon ? me : from).toUpperCase().slice(0, 12), moon = (askerIsMoon ? from : me).toUpperCase().slice(0, 12);
      const link = (partner) => r => {
        if (r.pair) throw fail(409, "ALREADY_PAIRED");
        r.pair = { with: partner, since, sun, moon };
        r.settings = { ...cleanSettings(r.settings), sun, moon, since };   // both pages now show the same sun, moon and anniversary
        return r;
      };
      await mutate(me, link(from));
      try { await mutate(from, link(me)); }
      catch (e) { await mutate(me, r => { r.pair = null; return r; }).catch(() => {}); throw e; }   // never leave only one side paired
    }
    const status = b.accept ? "accepted" : "declined";
    await updateLetter(me, b.id, l => { l.status = status; l.read = true; return l; });
    await patchSent(from, b.id, { status });
    await notify(from, { kind: b.accept ? "pair_yes" : "pair_no", by: me });
    return { ok: true, status };
  },

  async unpair(req) {
    const me = (await needUser(req)).rec;
    if (!me.pair) return { ok: true };
    const other = me.pair.with;
    await mutate(me.username, r => { r.pair = null; return r; });
    await store().delete(`g/${pairKey(me.username, other)}`).catch(() => {});      // their game goes with the pairing
    try {
      await mutate(other, r => { if (r.pair && r.pair.with === me.username) r.pair = null; return r; });
      await notify(other, { kind: "unpaired", by: me.username });
    } catch (e) { /* their account is gone: nothing to tell */ }
    return { ok: true };
  },

  async letterimg(req, res, b) {                              // photos are fetched one at a time, only when a letter is opened
    const me = (await needUser(req)).rec.username, id = String(b.id || "");
    if (!ID_RE.test(id)) throw fail(400, "SERVER");
    const v = await store().get(`${b.box === "out" ? "o" : "m"}/${me}/${id}`, { type: "json", consistency: "strong" });
    if (!v || !v.img) throw fail(404, "SERVER");
    return { img: v.img };
  },

  async outbox(req) {                                       // everything you've sent, newest first, with seen/not seen
    const me = (await needUser(req)).rec.username, st = store();
    const { blobs } = await st.list({ prefix: `o/${me}/` });
    const keys = blobs.map(x => x.key).sort().reverse().slice(0, 50);
    const items = await Promise.all(keys.map(async k => {
      const v = await st.get(k, { type: "json", consistency: "strong" });
      return v && { id: k.slice(k.lastIndexOf("/") + 1), to: v.to, text: v.text, hasImg: !!v.img, at: v.at, read: !!v.read, openedAt: v.openedAt || 0, re: v.re || null,
        type: v.type || "letter", since: v.since || "", status: v.status || "", role: v.role || "sun", gtype: v.gtype || "", gid: v.gid || "" };
    }));
    return { letters: items.filter(Boolean) };
  },

  async remove_sent(req, res, b) {                          // clears it from YOUR sent list only; they keep their copy
    const me = (await needUser(req)).rec.username;
    if (!ID_RE.test(String(b.id))) throw fail(400, "SERVER");
    const st = store(), cur = await st.get(`o/${me}/${b.id}`, { type: "json", consistency: "strong" });
    if (cur && (cur.type === "pair" || cur.type === "game") && cur.status === "pending") await st.delete(`m/${cur.to}/${b.id}`);   // withdrawn before they answered
    await st.delete(`o/${me}/${b.id}`);
    if (cur && cur.type === "game" && cur.status === "pending") {                                  // ...and a withdrawn game invite ends that game too
      const key = pairKey(me, cur.to), g = await getGame(key);
      if (g && g.data.id === cur.gid && g.data.status === "invited") await casGame(key, x => { x.status = "ended"; x.endedBy = me; return x; }).catch(() => {});
    }
    return { ok: true };
  },

  async remove(req, res, b) {
    const me = (await needUser(req)).rec.username;
    if (!ID_RE.test(String(b.id))) throw fail(400, "SERVER");
    await store().delete(`m/${me}/${b.id}`);
    return { ok: true };
  },

  /* ---- online status: every page pings, and learns whether the partner is around and whether a game is waiting ---- */
  async presence(req, res, b) {
    const rec = (await needUser(req)).rec, me = rec.username, st = store();
    await st.setJSON(`p/${me}`, { at: b.off ? 0 : Date.now() });
    const [mb, nb] = await Promise.all([st.list({ prefix: `m/${me}/` }), st.list({ prefix: `n/${me}/` })]);   // lets the page fetch new mail / notices straight away
    const sig = mb.blobs.length + ":" + (mb.blobs.map(x => x.key).sort().pop() || "") + "|" + nb.blobs.length;
    if (!rec.pair) return { pair: null, sig };
    const other = rec.pair.with, key = pairKey(me, other);
    const [pr, g] = await Promise.all([st.get(`p/${other}`, { type: "json", consistency: "strong" }), st.get(`g/${key}`, { type: "json", consistency: "strong" })]);
    const at = (pr && pr.at) || 0;
    return { sig, partner: other, online: Date.now() - at < ONLINE_MS, lastSeen: at,
      game: g ? { id: g.id, status: g.status, type: g.type, invitedBy: g.invitedBy, ver: g.ver || 0 } : null };
  },

  async game_get(req) {
    const { key } = await pairCtx(req);
    const cur = await getGame(key);
    return { game: cur ? cur.data : null };
  },

  async game_invite(req, res, b) {
    const { me, other, key } = await pairCtx(req);
    const type = String(b.type || ""); if (!GAMES[type]) throw fail(400, "SERVER");
    if (sendLimited(me)) throw fail(429, "TOO_MANY", { retry: 30 });
    const st = store(), cur = await getGame(key), old = cur && cur.data, now = Date.now();
    if (old && ((old.status === "invited" && now - old.updatedAt < 10 * 60000) || (old.status === "active" && now - old.updatedAt < 30 * 60000))) throw fail(409, "GAME_BUSY");
    const { blobs } = await st.list({ prefix: `m/${other}/` });
    if (blobs.length >= INBOX_MAX) throw fail(409, "INBOX_FULL");
    const gid = crypto.randomBytes(6).toString("hex"), id = now + "-" + crypto.randomBytes(4).toString("hex");
    const game = { id: gid, type, players: [me, other], status: "invited", invitedBy: me, turn: 0, first: 0, board: emptyBoard(type), winner: null, line: [],
      score: carryScore(old, me, other), chat: [], mailId: id, ver: (old && old.ver || 0) + 1, createdAt: now, updatedAt: now };
    const text = "GAME INVITE: " + GAMES[type];
    await st.setJSON(`m/${other}/${id}`, { from: me, type: "game", gtype: type, gid, status: "pending", text, at: now, read: false }, { onlyIfNew: true });   // offline? it waits in their Mail
    try { await st.setJSON(`o/${me}/${id}`, { to: other, type: "game", gtype: type, gid, status: "pending", text, at: now, read: false }, { onlyIfNew: true }); } catch (e) { console.error(e); }
    await st.setJSON(`g/${key}`, game);
    return { game };
  },

  async game_answer(req, res, b) {
    const { me, other, key } = await pairCtx(req);
    const cur = await getGame(key);
    if (!cur || cur.data.id !== String(b.gid) || cur.data.status !== "invited" || cur.data.invitedBy === me) throw fail(409, "GAME_GONE");
    const accept = !!b.accept, mailId = cur.data.mailId;
    const game = await casGame(key, g => { if (g.id !== String(b.gid) || g.status !== "invited") throw fail(409, "GAME_GONE"); g.status = accept ? "active" : "declined"; return g; });
    const status = accept ? "accepted" : "declined";
    try { await updateLetter(me, mailId, l => { l.status = status; l.read = true; return l; }); } catch (e) { console.error(e); }
    try { await patchSent(other, mailId, { status }); } catch (e) { console.error(e); }
    await notify(other, { kind: accept ? "game_yes" : "game_no", by: me, snip: GAMES[game.type] });
    return { game };
  },

  async game_move(req, res, b) {
    const { me, key } = await pairCtx(req);
    const game = await casGame(key, g => {
      if (g.id !== String(b.gid) || g.status !== "active") throw fail(409, "GAME_GONE");
      const idx = g.players.indexOf(me);
      if (idx < 0 || g.turn !== idx) throw fail(409, "NOT_YOUR_TURN");
      let cell;
      if (g.type === "ttt") { cell = Number(b.cell); if (!Number.isInteger(cell) || cell < 0 || cell > 8 || g.board[cell] !== null) throw fail(400, "BAD_MOVE"); }
      else { const col = Number(b.col); if (!Number.isInteger(col) || col < 0 || col > 6) throw fail(400, "BAD_MOVE");
        for (let r = 5; r >= 0; r--) if (g.board[r * 7 + col] === null) { cell = r * 7 + col; break; }
        if (cell === undefined) throw fail(400, "BAD_MOVE"); }
      g.board[cell] = idx; g.last = cell;
      const res2 = g.type === "ttt" ? tttCheck(g.board) : c4Check(g.board);
      if (res2) {
        g.status = "done"; g.winner = res2.w; g.line = res2.line;
        if (res2.w === -1) g.score.draws = (g.score.draws || 0) + 1; else g.score[g.players[res2.w]] = (g.score[g.players[res2.w]] || 0) + 1;
      } else g.turn = idx ^ 1;
      return g;
    });
    return { game };
  },

  async game_chat(req, res, b) {                               // a short message to your partner while you play
    const { me, key } = await pairCtx(req);
    const text = String(b.text || "").replace(/[\u0000-\u001F\u007F]/g, " ").replace(/\s+/g, " ").trim().slice(0, 200);
    if (!text) throw fail(400, "EMPTY");
    if (chatLimited(me)) throw fail(429, "TOO_MANY", { retry: 10 });
    const game = await casGame(key, g => {
      if (g.id !== String(b.gid) || (g.status !== "active" && g.status !== "done")) throw fail(409, "GAME_GONE");
      g.chat = (g.chat || []).concat({ from: me, text, at: Date.now() }).slice(-40);
      return g;
    });
    return { game };
  },

  async game_rematch(req) {                                    // same game again; whoever went second now goes first
    const { key } = await pairCtx(req);
    const game = await casGame(key, g => {
      if (g.status !== "done") return g;                       // the other person already started it
      g.status = "active"; g.board = emptyBoard(g.type); g.winner = null; g.line = []; g.last = null; g.first = g.first ^ 1; g.turn = g.first;
      return g;
    });
    return { game };
  },

  async game_quit(req) {                                       // leave a game, or take back an invite nobody answered yet
    const { me, other, key } = await pairCtx(req);
    const cur = await getGame(key);
    if (!cur) return { game: null };
    const st = store(), g0 = cur.data;
    if (g0.status === "invited" && g0.invitedBy === me) {
      await st.delete(`m/${other}/${g0.mailId}`).catch(() => {}); await st.delete(`o/${me}/${g0.mailId}`).catch(() => {});
    }
    if (g0.status === "ended" || g0.status === "declined") return { game: g0 };
    const game = await casGame(key, g => { g.status = "ended"; g.endedBy = me; return g; });
    return { game };
  },

  /* ---- admin only ---- */
  async admin_users(req) {
    await needAdmin(req);
    const st = store(), { blobs } = await st.list({ prefix: "u/" });
    const recs = await Promise.all(blobs.map(x => st.get(x.key, { type: "json", consistency: "strong" })));
    return { users: recs.filter(Boolean).map(r => ({ username: r.username, createdAt: r.createdAt, lastLoginAt: r.lastLoginAt, loginCount: r.loginCount || 0 }))
      .sort((a, b) => a.username < b.username ? -1 : 1) };
  },
  async admin_delete(req, res, b) {
    await needAdmin(req);
    const u = checkUsername(b.username), st = store();
    const gone = await getUser(u);
    if (!gone) throw fail(404, "NO_USER");
    if (gone.pair) await mutate(gone.pair.with, r => { if (r.pair && r.pair.with === u) r.pair = null; return r; }).catch(() => {});
    await st.delete("u/" + u);                                 // their logins stop working at once; the name becomes free again
    const { blobs } = await st.list({ prefix: `m/${u}/` });
    await Promise.all(blobs.map(x => st.delete(x.key)));       // and their inbox is erased
    const { blobs: nb } = await st.list({ prefix: `n/${u}/` });
    await Promise.all(nb.map(x => st.delete(x.key)));
    const { blobs: ob } = await st.list({ prefix: `o/${u}/` });
    await Promise.all(ob.map(x => st.delete(x.key)));
    await st.delete(`p/${u}`).catch(() => {});
    if (gone.pair) await st.delete(`g/${pairKey(u, gone.pair.with)}`).catch(() => {});
    return { ok: true };
  },
  async admin_reset(req, res, b) {
    await needAdmin(req);
    const u = checkUsername(b.username), pw = String(b.password || "");
    if (pw.length < 6 || pw.length > 100) throw fail(400, "WEAK_PASSWORD");
    const hashed = await makeHash(pw);
    await mutate(u, r => { r.pw = hashed; r.fails = { n: 0, until: 0 }; r.epoch = (r.epoch || 1) + 1; return r; });   // new password; signed out everywhere
    return { ok: true };
  },
  async admin_logout(req, res) {
    const a = await adminSession(req);
    if (a) await store().delete("a/" + a.hash);
    res.headers.append("Set-Cookie", "sm_admin=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
    return { ok: true };
  },

  async logout(req, res) {
    const s = await sessionUser(req);
    if (s) await store().delete("s/" + s.hash);
    res.headers.append("Set-Cookie", "sm_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
    return { ok: true };
  },
};

/* ---------------- entry point ---------------- */
async function handle(req, context) {
  const url = new URL(req.url);
  const name = url.pathname.replace(/^\/api\//, "");
  const out = (status, obj) => new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
  try {
    if (req.method !== "POST" || !Object.prototype.hasOwnProperty.call(routes, name)) throw fail(404, "SERVER");
    if (!/^application\/json/i.test(req.headers.get("content-type") || "")) throw fail(415, "SERVER");
    const origin = req.headers.get("origin");                 // block other websites from posting to us
    if (origin) { try { if (new URL(origin).host !== url.host) throw 0; } catch (e) { throw fail(403, "SERVER"); } }
    if (["signup", "login", "recover"].includes(name) && ipLimited((context && context.ip) || "?")) throw fail(429, "TOO_MANY", { retry: 60 });
    let body = {};
    const text = await req.text();
    if (text.length > (name === "send" ? 160000 : 20000)) throw fail(413, "SERVER");   // letters with a photo are bigger
    try { body = text ? JSON.parse(text) : {}; } catch (e) { throw fail(400, "SERVER"); }
    const res = out(200, null);                               // placeholder so routes can attach Set-Cookie
    const data = await routes[name](req, res, body && typeof body === "object" ? body : {});
    const final = out(200, data);
    for (const c of res.headers.getSetCookie()) final.headers.append("Set-Cookie", c);
    return final;
  } catch (e) {
    if (!e.status) { console.error(e); return out(500, { code: "SERVER" }); }
    return out(e.status, Object.assign({ code: e.code }, e.extra || {}));
  }
}

let ready = false;
async function init() {                                       // the table is created the first time the server wakes up, so there is no setup step
  if (ready) return;
  await DB.prepare("CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL, ver INTEGER NOT NULL DEFAULT 1) WITHOUT ROWID").run();
  ready = true;
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (!url.pathname.startsWith("/api/")) return env.ASSETS.fetch(request);
    const bad = () => new Response(JSON.stringify({ code: "SERVER" }), { status: 500, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
    if (!env.DB) return bad();
    DB = env.DB; SINGLE_SESSION = env.SINGLE_SESSION === "1"; ADMIN_PASSWORD = env.ADMIN_PASSWORD || "";
    try { await init(); } catch (e) { console.error(e); return bad(); }
    return handle(request, { ip: request.headers.get("CF-Connecting-IP") });
  },
};
