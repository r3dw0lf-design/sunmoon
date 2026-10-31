/* Sun & Moon - account API as a Netlify Function (served at /api/*).
   ONE shared list of accounts for everyone, stored in Netlify Blobs (strong consistency).
   - A username is claimed with a "write only if new" call, so two people can never both get it,
     even if they click at the same instant from different countries.
   - Passwords + recovery codes are stored only as salted scrypt hashes.
   - Logins are HttpOnly cookies backed by server-side sessions.
   Env vars (Netlify > Site settings > Environment variables):
     ADMIN_PASSWORD     optional: a different password for the ADMIN login (replaces the built-in one)
     SINGLE_SESSION=1   logging in on a new device logs the old one out */
import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(crypto.scrypt);
const USER_RE = /^[a-z0-9_.-]{3,20}$/;
const SESSION_MS = 365 * 24 * 3600 * 1000;
const SINGLE_SESSION = process.env.SINGLE_SESSION === "1";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";      // optional override (Netlify setting)
/* The built-in ADMIN password is kept here only as a salted scrypt hash, never as readable text, so even if someone
   downloads this file they cannot read it. Log in as ADMIN with your password; to change it later, set ADMIN_PASSWORD. */
const ADMIN_BUILTIN = { salt: "H+Z8r2xCffAVILM54j82Mg==", hash: "0no3ZX30M6lWzMiCCWYGBTslzv3CybNQASqcJCK4zhc=" };
const ADMIN_MS = 8 * 3600 * 1000;                          // an admin login lasts 8 hours
const store = () => getStore({ name: "sunmoon-accounts", consistency: "strong" });

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
const pubUser = (rec, lastLoginAt) => ({ username: rec.username, settings: rec.settings, loginCount: rec.loginCount,
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
const INBOX_MAX = 100;
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
    const rec = { username, pw, rc, settings: cleanSettings(b.settings), createdAt: now, lastLoginAt: now, loginCount: 1, epoch: 1, uid: crypto.randomBytes(8).toString("hex"), fails: { n: 0, until: 0 } };
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
    const to = checkUsername(b.to), text = cleanLetterText(b.text);
    if (!text) throw fail(400, "EMPTY");
    if (sendLimited(me)) throw fail(429, "TOO_MANY", { retry: 30 });
    if (!(await getUser(to))) throw fail(404, "NO_USER");
    const st = store();
    const { blobs } = await st.list({ prefix: `m/${to}/` });
    if (blobs.length >= INBOX_MAX) throw fail(409, "INBOX_FULL");
    const id = Date.now() + "-" + crypto.randomBytes(4).toString("hex");
    await st.setJSON(`m/${to}/${id}`, { from: me, text, at: Date.now(), read: false }, { onlyIfNew: true });
    return { ok: true };
  },

  async inbox(req) {
    const me = (await needUser(req)).rec.username, st = store();
    const { blobs } = await st.list({ prefix: `m/${me}/` });
    const keys = blobs.map(x => x.key).sort().reverse().slice(0, 50);   // newest first
    const items = await Promise.all(keys.map(async k => {
      const v = await st.get(k, { type: "json", consistency: "strong" });
      return v && { id: k.slice(k.lastIndexOf("/") + 1), from: v.from, text: v.text, at: v.at, read: !!v.read };
    }));
    return { letters: items.filter(Boolean) };
  },

  async read(req, res, b) {
    const me = (await needUser(req)).rec.username;
    await updateLetter(me, b.id, l => Object.assign(l, { read: true }));
    return { ok: true };
  },

  async remove(req, res, b) {
    const me = (await needUser(req)).rec.username;
    if (!ID_RE.test(String(b.id))) throw fail(400, "SERVER");
    await store().delete(`m/${me}/${b.id}`);
    return { ok: true };
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
    if (!(await getUser(u))) throw fail(404, "NO_USER");
    await st.delete("u/" + u);                                 // their logins stop working at once; the name becomes free again
    const { blobs } = await st.list({ prefix: `m/${u}/` });
    await Promise.all(blobs.map(x => st.delete(x.key)));       // and their inbox is erased
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
export default async (req, context) => {
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
    if (text.length > 20000) throw fail(413, "SERVER");
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
};

export const config = { path: "/api/*" };
