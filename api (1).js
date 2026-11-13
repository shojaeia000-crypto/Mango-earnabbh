// Tap Earn API: stores all users in users.json inside a (private) GitHub repo.
const crypto = require('crypto');
const { GH_TOKEN, GH_REPO, GH_BRANCH = 'main', ADMIN_USER = 'امیرمحمد', ADMIN_PASS = '15679' } = process.env;
const API = `https://api.github.com/repos/${GH_REPO}/contents/users.json`;
const H = { Authorization: `Bearer ${GH_TOKEN}`, 'User-Agent': 'tap-earn', Accept: 'application/vnd.github+json' };
const TG = [100, 400, 500];
const R = (c, b) => ({ statusCode: c, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) });
const num = (v, m) => Math.max(0, Math.min(m, Math.floor(+v) || 0));
const pub = ({ salt, pw, ...r }) => r;
const hp = (p, s) => crypto.scryptSync(String(p), s, 32).toString('hex');
const sig = s => crypto.createHmac('sha256', GH_TOKEN).update(s).digest('hex');
const sign = (role, name) => { const p = Buffer.from(`${role}|${name}|${Date.now() + 2592e6}`).toString('base64url'); return p + '.' + sig(p); };
function verify(t) {
  if (!t || !t.includes('.')) return null;
  const [p, s] = t.split('.');
  if (sig(p) !== s) return null;
  const [role, name, exp] = Buffer.from(p, 'base64url').toString().split('|');
  return +exp > Date.now() ? { role, name } : null;
}
let C = null, CT = 0;
async function read(fresh) {
  if (!fresh && C && Date.now() - CT < 4000) return C;
  const r = await fetch(API + '?ref=' + GH_BRANCH, { headers: H });
  if (r.status === 404) return (C = { db: { users: {} }, sha: null }, CT = Date.now(), C);
  if (!r.ok) throw new Error('gh ' + r.status);
  const j = await r.json();
  C = { db: JSON.parse(Buffer.from(j.content, 'base64').toString()), sha: j.sha }; CT = Date.now();
  return C;
}
async function write(db, sha) {
  const r = await fetch(API, { method: 'PUT', headers: H, body: JSON.stringify({ message: 'update users', branch: GH_BRANCH, sha: sha || undefined, content: Buffer.from(JSON.stringify(db)).toString('base64') }) });
  C = null;
  if (!r.ok) { const e = new Error('gh ' + r.status); e.status = r.status; throw e; }
}
async function mutate(fn) { // read -> change -> write, retry on conflicts
  for (let i = 0; i < 4; i++) {
    const { db, sha } = await read(true);
    const out = fn(db) || {};
    if (out.err || out.noWrite) return [out, db];
    try { await write(db, sha); return [out, db]; } catch (e) { if (e.status !== 409 && e.status !== 422) throw e; }
  }
  throw new Error('conflict');
}
const lb = db => Object.values(db.users).map(u => ({ name: u.name, lv: Math.min(u.lvl + 1, 3), taps: u.taps, coins: u.coins })).sort((a, b) => b.taps - a.taps).slice(0, 50);
function setLevel(x) { x.rewards = [...Array(x.lvl).keys()]; x.prog = num(x.prog, x.lvl > 2 ? 0 : TG[x.lvl] - 1); }

exports.handler = async ev => {
  if (!GH_TOKEN || !GH_REPO) return R(500, { err: 'Server not configured' });
  let b; try { b = JSON.parse(ev.body || '{}'); } catch (e) { return R(400, { err: 'Bad request' }); }
  try {
    const a = b.a;
    if (a === 'lb') return R(200, { lb: lb((await read()).db) });
    if (a === 'signup') {
      const n = String(b.u || '').trim(), k = n.toLowerCase();
      if (!/^[\p{L}\p{N}_.-]{3,16}$/u.test(n)) return R(400, { err: 'Username: 3-16 letters/numbers' });
      if (String(b.p || '').length < 4) return R(400, { err: 'Password must be at least 4 characters' });
      if (k === ADMIN_USER.toLowerCase()) return R(400, { err: 'Username already taken' });
      const [o] = await mutate(db => {
        if (db.users[k]) return { err: 'Username already taken' };
        const salt = crypto.randomBytes(8).toString('hex');
        db.users[k] = { name: n, salt, pw: hp(b.p, salt), created: Date.now(), taps: 0, lvl: 0, prog: 0, coins: 0, bonus: 0, rewards: [], adm: 0 };
        return { user: pub(db.users[k]), t: sign('u', k) };
      });
      return o.err ? R(400, o) : R(200, o);
    }
    if (a === 'login') {
      if (b.u === ADMIN_USER && b.p === ADMIN_PASS) return R(200, { admin: true, t: sign('a', 'admin') });
      const x = (await read(true)).db.users[String(b.u || '').trim().toLowerCase()];
      if (!x || hp(b.p, x.salt) !== x.pw) return R(401, { err: 'Wrong username or password' });
      return R(200, { user: pub(x), t: sign('u', x.name.toLowerCase()) });
    }
    const s = verify(b.t);
    if (!s) return R(401, { err: 'auth' });
    if (s.role === 'u' && a === 'sync') {
      if (!b.u) { const { db } = await read(); const x = db.users[s.name]; return x ? R(200, { user: pub(x), lb: lb(db) }) : R(401, { err: 'auth' }); }
      const [o, db] = await mutate(db => {
        const x = db.users[s.name]; if (!x) return { err: 'auth' };
        const c = b.u;
        if (c.adm !== x.adm) return { over: 1, user: pub(x), noWrite: 1 }; // admin changed it: admin wins
        x.taps = num(c.taps, 1e9); x.lvl = num(c.lvl, 3); x.coins = num(c.coins, 1e12); x.bonus = num(c.bonus, 1e9); x.prog = c.prog; setLevel(x);
        return { user: pub(x) };
      });
      return o.err ? R(401, o) : R(200, { ...o, lb: lb(db) });
    }
    if (s.role === 'a') {
      if (a === 'alist') return R(200, { users: Object.entries((await read(true)).db.users).map(([key, u]) => ({ key, ...pub(u) })) });
      if (a === 'aset') {
        const f = b.f || {};
        const [o] = await mutate(db => {
          const x = db.users[b.n]; if (!x) return { err: 'No such user' };
          if ('taps' in f) x.taps = num(f.taps, 1e9);
          if ('coins' in f) x.coins = num(f.coins, 1e12);
          if ('bonus' in f) x.bonus = num(f.bonus, 1e9);
          if ('lvl' in f) x.lvl = num(f.lvl, 3);
          if ('prog' in f) x.prog = f.prog;
          setLevel(x);
          if (f.pw && String(f.pw).length >= 4) { x.salt = crypto.randomBytes(8).toString('hex'); x.pw = hp(f.pw, x.salt); }
          x.adm = (x.adm || 0) + 1;
          return {};
        });
        return o.err ? R(400, o) : R(200, {});
      }
      if (a === 'adel') { await mutate(db => { delete db.users[b.n]; }); return R(200, {}); }
    }
    return R(403, { err: 'auth' });
  } catch (e) { return R(500, { err: 'Server error' }); }
};
