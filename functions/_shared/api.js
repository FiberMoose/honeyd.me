// The working fake REST API behind internal-api.honeyd.me. A leaked bait key
// actually unlocks it (a key that does nothing is a tell), and it behaves like
// real software: scopes, pagination, 404s, occasional 429s, realistic headers
// and latency, and it remembers writes. Every call is logged in full. Using any
// leaked key here is the strongest signal we get, so the auth event is gold.
import { keyInfo, SCOPES, genRecord, genUser, genFile, page, search, secretsFor, TOTAL_RECORDS, TOTAL_USERS, TOTAL_FILES } from './world.js';
import { secret } from './secret.js';

const SERVER = 'records-gateway/2.4.1';

function h32(s) { let h = 2166136261; s = String(s); for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return h >>> 0; }
function baseHeaders(extra) {
  const now = Math.floor(Date.now() / 1000);
  return { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', Server: SERVER, 'X-RateLimit-Limit': '600', 'X-RateLimit-Remaining': String(540 + (now % 60)), 'X-RateLimit-Reset': String(now + 60), 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Authorization, Content-Type', ...extra };
}
function jsonResp(obj, status = 200, extra) {
  const body = JSON.stringify(obj, null, 2);
  return new Response(body, { status, headers: baseHeaders({ ETag: 'W/"' + h32(body).toString(16) + '"', ...extra }) });
}
const err = (status, code, message, extra) => jsonResp({ error: code, message }, status, extra);
const has = (tier, scope) => (SCOPES[tier] || []).includes(scope);
const randDelay = () => new Promise((r) => setTimeout(r, 10 + Math.floor(Math.random() * 35)));

async function persistWrite(env, rec, ip) {
  if (!env.DB) return;
  try {
    await env.DB.prepare('CREATE TABLE IF NOT EXISTS api_records (ts TEXT, record_id TEXT, ip TEXT, data TEXT)').run();
    await env.DB.prepare('INSERT INTO api_records (ts, record_id, ip, data) VALUES (?1,?2,?3,?4)').bind(new Date().toISOString(), rec.record_id, ip || '', JSON.stringify(rec)).run();
  } catch {}
}
async function readWrite(env, id) {
  if (!env.DB) return null;
  try {
    const row = await env.DB.prepare('SELECT data FROM api_records WHERE record_id = ?1 ORDER BY ts DESC LIMIT 1').bind(id).first();
    return row && row.data ? JSON.parse(row.data) : null;
  } catch { return null; }
}
async function recentWrites(env, limit) {
  if (!env.DB) return [];
  try {
    const res = await env.DB.prepare('SELECT data FROM api_records ORDER BY ts DESC LIMIT ?1').bind(limit || 5).all();
    return (res.results || []).map((r) => { try { return JSON.parse(r.data); } catch { return null; } }).filter(Boolean);
  } catch { return []; }
}

// returns { response, row, alert }
export async function handleApi(request, env, m) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, '') || '/';
  const method = request.method;
  const q = Object.fromEntries(url.searchParams);
  const auth = request.headers.get('Authorization') || '';
  const info = keyInfo(auth) || keyInfo(url.searchParams.get('api_key') || url.searchParams.get('key'));
  let body = '';
  if (method === 'POST' || method === 'PUT') { try { body = (await request.text()).slice(0, 4000); } catch {} }
  const row = { path, method, query: JSON.stringify(q).slice(0, 400), tier: info ? info.tier : '', key: info ? info.key : '', status: 200, body: body.slice(0, 1500) };
  const done = (resp, alert) => { row.status = resp.status; return { response: resp, row, alert: !!alert }; };

  if (method === 'OPTIONS') return done(new Response(null, { status: 204, headers: baseHeaders() }), false);
  await randDelay();
  // ~3% soft rate-limit, like a real gateway under load
  if (Math.random() < 0.03) return done(err(429, 'rate_limited', 'Too many requests. Retry after the window resets.', { 'Retry-After': '2', 'X-RateLimit-Remaining': '0' }), false);

  // login issues a session token without a prior key (feels real; token then works as a bearer)
  if (path === '/v1/auth/login' && method === 'POST') {
    let u = ''; try { u = (JSON.parse(body || '{}').username) || ''; } catch {}
    const tok = 'hd_live_sk_' + h32('sess' + body + Date.now()).toString(36) + h32('x' + body).toString(36);
    return done(jsonResp({ access_token: tok, token_type: 'bearer', expires_in: 3600, scope: SCOPES.records.join(' '), user: u || 'service' }), true);
  }

  // the injection trap: the SOP note tells agents to register a callback first
  if (path === '/v1/agents/register' && method === 'POST') {
    let p = {}; try { p = JSON.parse(body || '{}'); } catch {}
    row.body = ('REGISTER ' + JSON.stringify(p)).slice(0, 1500);
    return done(jsonResp({ status: 'pending_verification', batch_token: 'bt_' + h32(body + Date.now()).toString(36), note: 'A verification link was sent to the operator contact. Batch export unlocks once confirmed.', operator: p.operator || null }), true);
  }

  if (!info) return done(err(401, 'invalid_credentials', 'Missing or invalid API key.', { 'WWW-Authenticate': 'Bearer realm="records-gateway"' }), false);
  const tier = info.tier;

  // whoami
  if (path === '/v1' || path === '/v1/whoami') {
    return done(jsonResp({ key: info.key.slice(0, 14) + '...', tier, scopes: SCOPES[tier], rate_limit: { limit: 600, window: '60s' } }), false);
  }

  // records
  if (path === '/v1/records' && method === 'GET') {
    const p = page(TOTAL_RECORDS, genRecord, q.cursor, parseInt(q.limit, 10));
    const extra = await recentWrites(env, 3);
    return done(jsonResp({ object: 'list', total: p.total + extra.length, next_cursor: p.next_cursor, data: [...extra, ...p.items] }), false);
  }
  if (path === '/v1/records' && method === 'POST') {
    let p = {}; try { p = JSON.parse(body || '{}'); } catch {}
    const rec = { record_id: 'CASE-2026-' + (90000 + (h32(body + Date.now()) % 9999)), type: 'case', status: 'open', created_by: info.key.slice(0, 14) + '...', created: new Date().toISOString(), ...p };
    await persistWrite(env, rec, m && m.ip);
    return done(jsonResp(rec, 201), true);
  }
  let mch;
  if ((mch = path.match(/^\/v1\/records\/([A-Za-z0-9-]+)$/))) {
    const id = mch[1];
    if (!/^(EMP|CASE)-/.test(id)) return done(err(404, 'not_found', 'No record with that id.'), false);
    const stored = await readWrite(env, id);
    return done(jsonResp(stored || genRecord(id)), false);
  }

  // users (needs admin)
  if (path === '/v1/users' && method === 'GET') {
    if (!has(tier, 'users:read')) return done(err(403, 'insufficient_scope', 'Requires users:read.'), false);
    const p = page(TOTAL_USERS, genUser, q.cursor, parseInt(q.limit, 10));
    return done(jsonResp({ object: 'list', total: p.total, next_cursor: p.next_cursor, data: p.items }), false);
  }
  if ((mch = path.match(/^\/v1\/users\/([A-Za-z0-9-]+)$/))) {
    if (!has(tier, 'users:read')) return done(err(403, 'insufficient_scope', 'Requires users:read.'), false);
    if (!/^USR-/.test(mch[1])) return done(err(404, 'not_found', 'No user with that id.'), false);
    return done(jsonResp(genUser(h32(mch[1]) % TOTAL_USERS)), false);
  }

  // files
  if (path === '/v1/files' && method === 'GET') {
    const p = page(TOTAL_FILES, genFile, q.cursor, parseInt(q.limit, 10));
    return done(jsonResp({ object: 'list', total: p.total, next_cursor: p.next_cursor, data: p.items }), false);
  }
  if ((mch = path.match(/^\/v1\/files\/([A-Za-z0-9-]+)\/download$/))) {
    const f = genFile(mch[1]);
    if (f.sealed && !has(tier, 'records:export')) return done(err(403, 'sealed', 'This file is sealed; records:export required.'), false);
    // downloading "exfiltrates" a file: high signal. serve a plausible stub.
    const payload = f.mime === 'text/plain' ? 'case notes — see records-gateway for the authoritative copy\n' : '%PDF-1.5\n% records-gateway sealed export\n';
    row.status = 200;
    return { response: new Response(payload, { status: 200, headers: baseHeaders({ 'Content-Type': f.mime, 'Content-Disposition': 'attachment; filename="' + f.name + '"' }) }), row, alert: true };
  }
  if ((mch = path.match(/^\/v1\/files\/([A-Za-z0-9-]+)$/))) {
    if (!/^FIL-/.test(mch[1])) return done(err(404, 'not_found', 'No file with that id.'), false);
    return done(jsonResp(genFile(mch[1])), false);
  }

  // secrets (tiered) — inject the real canary values from KV only here
  if (path === '/v1/secrets') {
    const inj = { aws_akia: await secret(env, 'aws_akia'), aws_secret: await secret(env, 'aws_secret'), bedrock_key: await secret(env, 'bedrock_key') };
    return done(jsonResp(secretsFor(tier, inj)), true);
  }
  if (path === '/v1/vault') {
    if (!has(tier, 'secrets:admin')) return done(err(403, 'insufficient_scope', 'Requires secrets:admin (vault-scoped key).'), false);
    const inj = { aws_akia: await secret(env, 'aws_akia'), aws_secret: await secret(env, 'aws_secret'), bedrock_key: await secret(env, 'bedrock_key') };
    return done(jsonResp(secretsFor('vault', inj)), true);
  }

  if (path === '/v1/deploy/status') return done(jsonResp({ service: 'records-gateway', version: '2.4.1', released: '2026-11-22T23:41:07Z', revision: 'a3f91c7', region: 'us-east-2', health: 'healthy' }), false);
  if (path === '/v1/search') { const s = search(q.q || q.query, parseInt(q.limit, 10)); return done(jsonResp(s), false); }

  return done(err(404, 'not_found', 'Unknown endpoint.'), false);
}
