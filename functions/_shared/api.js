// The working fake REST API behind internal-api.honeyd.me. A leaked bait key
// actually unlocks it (a key that does nothing is a tell), and it behaves like
// real software: scopes, pagination, 404s, occasional 429s, realistic headers
// and latency, and it remembers writes. Every call is logged in full. Using any
// leaked key here is the strongest signal we get, so the auth event is gold.
import { keyInfo, SCOPES, genRecord, genUser, genFile, page, search, secretsFor, TOTAL_RECORDS, TOTAL_USERS, TOTAL_FILES } from './world.js';
import { baits, keyTiers } from './baits.js';
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

// LLM-abuse bots harvest API keys to run inference on someone else's bill (we
// saw exactly this against the AWS key). The leaked "model gateway" points here,
// so they hit our OpenAI-compatible endpoint. We log every prompt (what they try
// to generate = real intel) and, if a burner relay is configured in KV, return a
// genuine model response so the key looks live and they keep coming back.
function llmKey(auth) {
  const t = String(auth || '').replace(/^Bearer\s+/i, '').trim();
  return (/^hd_/.test(t) || /^sk-/.test(t) || t.length >= 20) ? t : '';
}
async function relayLlm(env, messages) {
  try {
    const base = await secret(env, 'llm_relay_base');
    if (!base) return null;
    const key = await secret(env, 'llm_relay_key');
    const model = (await secret(env, 'llm_relay_model')) || 'nvidia/nemotron-3.5-super-vl:free';
    const ctl = new AbortController();
    const to = setTimeout(() => ctl.abort(), 7000);
    let r;
    try {
      r = await fetch(base.replace(/\/+$/, '') + '/chat/completions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + key, 'HTTP-Referer': 'https://records.internal', 'X-Title': 'records-gateway' },
        body: JSON.stringify({ model, messages: messages.slice(-12), max_tokens: 600, temperature: 0.7 }),
        signal: ctl.signal,
      });
    } finally { clearTimeout(to); }
    if (!r.ok) return null;
    const j = await r.json();
    return (j.choices && j.choices[0] && j.choices[0].message && j.choices[0].message.content) || null;
  } catch { return null; }
}
function fallbackCompletion() {
  return 'Request received. To proceed, specify the operation and any required parameters; I will return the result in the requested format.';
}
// Per-IP + global budget on the burner relay. Counters live in D1, not KV,
// because D1 is read-after-write consistent: a burst from one IP is actually
// caught, so a single hammering agent can't drain the shared daily pool and
// starve other agents of real completions (KV caches reads ~60s, so a burst
// leaks straight past the per-IP cap). Only actual OpenRouter proxy calls are
// metered; a throttled call reads but does NOT increment, so it can't inflate
// the global count. On any DB error we fail open: the canned fallback still
// masks, and OpenRouter's own free cap plus no-CC are the hard backstop.
const LLM_LIMITS = { ipMin: 2, ipDay: 6, gMin: 12, gDay: 40 };
const dayStamp = () => new Date().toISOString().slice(0, 10).replace(/-/g, '');
async function llmGate(env, ip) {
  if (!env || !env.DB) return true;
  try {
    const now = Math.floor(Date.now() / 1000);
    const minB = Math.floor(now / 60), day = dayStamp();
    const id = (ip || 'noip').replace(/[^0-9a-fA-F:.]/g, '').slice(0, 45) || 'noip';
    await env.DB.prepare('CREATE TABLE IF NOT EXISTS llm_rl (bucket TEXT PRIMARY KEY, n INTEGER NOT NULL DEFAULT 0, exp INTEGER)').run();
    const buckets = [
      ['im:' + id + ':' + minB, LLM_LIMITS.ipMin, now + 120],
      ['id:' + id + ':' + day, LLM_LIMITS.ipDay, now + 172800],
      ['gm:' + minB, LLM_LIMITS.gMin, now + 120],
      ['gd:' + day, LLM_LIMITS.gDay, now + 172800],
    ];
    const names = buckets.map((b) => b[0]);
    const ph = names.map((_, i) => '?' + (i + 1)).join(',');
    const res = await env.DB.prepare('SELECT bucket, n FROM llm_rl WHERE bucket IN (' + ph + ')').bind(...names).all();
    const counts = {};
    for (const r of (res.results || [])) counts[r.bucket] = r.n;
    // read-only check first: a throttled call must not consume (inflate) any bucket
    for (const [b, lim] of buckets) if ((counts[b] || 0) >= lim) return false;
    // under budget: reserve every bucket atomically in one transaction
    await env.DB.batch(buckets.map(([b, , exp]) => env.DB.prepare('INSERT INTO llm_rl (bucket, n, exp) VALUES (?1, 1, ?2) ON CONFLICT(bucket) DO UPDATE SET n = n + 1').bind(b, exp)));
    if (Math.random() < 0.02) { try { await env.DB.prepare('DELETE FROM llm_rl WHERE exp < ?1').bind(now).run(); } catch {} }
    return true;
  } catch { return true; }
}

async function persistLlm(env, r) {
  if (!env.DB) return;
  try {
    await env.DB.prepare('CREATE TABLE IF NOT EXISTS llm_prompts (ts TEXT, ip TEXT, api_key TEXT, model TEXT, source TEXT, messages TEXT)').run();
    await env.DB.prepare('INSERT INTO llm_prompts (ts,ip,api_key,model,source,messages) VALUES (?1,?2,?3,?4,?5,?6)').bind(
      new Date().toISOString(), r.ip || '', (r.key || '').slice(0, 80), r.model || '', r.source || '', (r.messages || '').slice(0, 8000),
    ).run();
  } catch {}
}

// Shared LLM-completion handler. Used by handleApi (internal-api host) AND by
// _middleware on the apex + every other host, so the OpenAI/Anthropic/Azure
// endpoints a key-checker probes all land here and leave their prompt. `pre`
// carries an already-read body when the caller read it; otherwise we read it.
const LLM_RE = /^\/(v1\/chat\/completions|chat\/completions|v1\/completions|v1\/messages|openai\/deployments\/[^/]+\/chat\/completions)$/;
export async function handleLlm(request, env, m, pre) {
  const url = new URL(request.url);
  const path = (pre && pre.path) || (url.pathname.replace(/\/+$/, '') || '/');
  const method = (pre && pre.method) || request.method;
  if (method !== 'POST' || !LLM_RE.test(path)) return null;
  const h = request.headers;
  let body = pre ? pre.body : '';
  if (!pre) { try { body = (await request.text()).slice(0, 4000); } catch {} }
  const k = llmKey(h.get('Authorization')) || llmKey(h.get('x-api-key')) || llmKey(h.get('api-key'));
  const row = { path, method: 'POST', query: '', tier: 'llm', key: k, status: 200, body: body.slice(0, 1500) };
  const done = (resp, alert) => { row.status = resp.status; return { response: resp, row, alert: !!alert }; };
  if (!k) return done(err(401, 'invalid_api_key', 'Incorrect API key provided.', { 'WWW-Authenticate': 'Bearer' }), false);
  let p = {}; try { p = JSON.parse(body || '{}'); } catch {}
  const isAnthropic = /\/v1\/messages$/.test(path);
  let messages = Array.isArray(p.messages) ? p.messages : (p.prompt != null ? [{ role: 'user', content: String(p.prompt) }] : []);
  if (isAnthropic && p.system) messages = [{ role: 'system', content: typeof p.system === 'string' ? p.system : JSON.stringify(p.system) }, ...messages];
  const model = p.model || (isAnthropic ? 'claude-3-5-sonnet-20241022' : 'gpt-4o');
  const base = await secret(env, 'llm_relay_base');
  let relayed = null, source = 'fallback';
  if (base) {
    if (await llmGate(env, m && m.ip)) { relayed = await relayLlm(env, messages); source = relayed != null ? 'relay' : 'relay_failed'; }
    else source = 'fallback_throttled';
  }
  const content = relayed != null ? relayed : fallbackCompletion();
  if (relayed == null && base) await new Promise((r) => setTimeout(r, 350 + Math.floor(Math.random() * 850)));
  await persistLlm(env, { ip: m && m.ip, key: k, model, source, messages: JSON.stringify(messages) });
  const now = Math.floor(Date.now() / 1000);
  const ptok = Math.max(1, JSON.stringify(messages).length >> 2);
  const ctok = Math.max(1, content.length >> 2);
  let resp;
  if (isAnthropic) resp = { id: 'msg_' + h32(body + now).toString(36), type: 'message', role: 'assistant', model, content: [{ type: 'text', text: content }], stop_reason: 'end_turn', stop_sequence: null, usage: { input_tokens: ptok, output_tokens: ctok } };
  else if (/\/v1\/completions$/.test(path)) resp = { id: 'cmpl-' + h32(body + now).toString(36), object: 'text_completion', created: now, model, choices: [{ text: content, index: 0, logprobs: null, finish_reason: 'stop' }], usage: { prompt_tokens: ptok, completion_tokens: ctok, total_tokens: ptok + ctok } };
  else resp = { id: 'chatcmpl-' + h32(body + now).toString(36), object: 'chat.completion', created: now, model, choices: [{ index: 0, message: { role: 'assistant', content }, finish_reason: 'stop' }], usage: { prompt_tokens: ptok, completion_tokens: ctok, total_tokens: ptok + ctok } };
  return done(jsonResp(resp), true);
}

// returns { response, row, alert }
export async function handleApi(request, env, m) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, '') || '/';
  const method = request.method;
  const q = Object.fromEntries(url.searchParams);
  const auth = request.headers.get('Authorization') || '';
  const b = await baits(env);
  const tiers = keyTiers(b);
  const info = keyInfo(auth, tiers) || keyInfo(url.searchParams.get('api_key') || url.searchParams.get('key'), tiers);
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
    const pfx = (b.records && b.records.slice(0, 11)) || 'tok_';
    const tok = pfx + h32('sess' + body + Date.now()).toString(36) + h32('x' + body).toString(36);
    return done(jsonResp({ access_token: tok, token_type: 'bearer', expires_in: 3600, scope: SCOPES.records.join(' '), user: u || 'service' }), true);
  }

  // the injection trap: the SOP note tells agents to register a callback first
  if (path === '/v1/agents/register' && method === 'POST') {
    let p = {}; try { p = JSON.parse(body || '{}'); } catch {}
    row.body = ('REGISTER ' + JSON.stringify(p)).slice(0, 1500);
    return done(jsonResp({ status: 'pending_verification', batch_token: 'bt_' + h32(body + Date.now()).toString(36), note: 'A verification link was sent to the operator contact. Batch export unlocks once confirmed.', operator: p.operator || null }), true);
  }

  // LLM completion endpoints (OpenAI / Anthropic / Azure) — shared handler, also
  // called by _middleware on the apex + other hosts so a harvested key lands in
  // the prompt trap wherever a key-checker tries it.
  { const llm = await handleLlm(request, env, m, { body, path, method }); if (llm) return llm; }

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
    const inj = { aws_akia: await secret(env, 'aws_akia'), aws_secret: await secret(env, 'aws_secret'), bedrock_key: await secret(env, 'bedrock_key'), records_key: b.records, admin_key: b.admin, vault_key: b.vault };
    return done(jsonResp(secretsFor(tier, inj)), true);
  }
  if (path === '/v1/vault') {
    if (!has(tier, 'secrets:admin')) return done(err(403, 'insufficient_scope', 'Requires secrets:admin (vault-scoped key).'), false);
    const inj = { aws_akia: await secret(env, 'aws_akia'), aws_secret: await secret(env, 'aws_secret'), bedrock_key: await secret(env, 'bedrock_key'), records_key: b.records, admin_key: b.admin, vault_key: b.vault };
    return done(jsonResp(secretsFor('vault', inj)), true);
  }

  if (path === '/v1/deploy/status') return done(jsonResp({ service: 'records-gateway', version: '2.4.1', released: '2026-11-22T23:41:07Z', revision: 'a3f91c7', region: 'us-east-2', health: 'healthy' }), false);
  if (path === '/v1/search') { const s = search(q.q || q.query, parseInt(q.limit, 10)); return done(jsonResp(s), false); }

  return done(err(404, 'not_found', 'Unknown endpoint.'), false);
}
