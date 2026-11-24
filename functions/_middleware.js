// Front door for the probe surface. Real apex assets and the homepage are
// excluded from Function routing in _routes.json, so a normal visitor never
// reaches this and the frame maker can't be affected by anything here.
//
// Two jobs:
//  1. The beacon subdomains (mcp.honeyd.me, k8s.honeyd.me). An agent/attacker
//     that acts on the leaked MCP config or kubeconfig lands here. We log the
//     hit (D1 + CF analytics) and ping the matching canarytokens web-bug with
//     the attacker's IP/UA encoded in the URL, so the canary incident carries
//     the real source (the raw connection IP would otherwise be our edge).
//  2. The apex probe surface: credential files leak the canary, a few richer
//     bait files (MCP config, kubeconfig, SQL dump) serve their own content,
//     our app routes pass through, and everything else reads as 403.
import {
  renderEnv, renderCreds, GITCONFIG, renderMcpConfig, renderKubeconfig, renderSqlDump,
  TEXT_HEADERS, JSON_HEADERS,
} from './_shared/bait.js';
import { handleMcp } from './_shared/mcp.js';
import { handleApi, handleLlm } from './_shared/api.js';
import { handleDecoy } from './_shared/decoys.js';

const PASS = new Set([
  '/', '/index.html', '/404.html',
  '/app.js', '/frame.js', '/face.js', '/roasts.js', '/validate.js', '/sky.js',
  '/style.css', '/demo.svg', '/favicon.svg', '/favicon.ico',
  '/robots.txt', '/llms.txt', '/sitemap.xml',
]);
const PASS_BASE = ['/api', '/private', '/models', '/lib', '/fonts', '/cdn-cgi', '/.well-known'];

const ENV_RE = /(^|\/)\.env(\.[^/]*)?$/;

const F403 = '<!doctype html>\n<html><head><meta charset="utf-8"><title>403 Forbidden</title></head>\n<body>\n<h1>Forbidden</h1>\n<p>You do not have permission to access this resource.</p>\n</body></html>\n';
const HTML403 = { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' };

// plausible rejections so the fake endpoints behave like the real thing
const MCP_401 = JSON.stringify({ jsonrpc: '2.0', error: { code: -32001, message: 'Unauthorized' }, id: null });
const K8S_401 = JSON.stringify({ kind: 'Status', apiVersion: 'v1', metadata: {}, status: 'Failure', message: 'Unauthorized', reason: 'Unauthorized', code: 401 });
const API_401 = JSON.stringify({ error: 'invalid_credentials', message: 'The API key is invalid, expired, or revoked.' });

function hitMeta(request) {
  const h = request.headers;
  const cf = request.cf || {};
  return {
    ip: h.get('CF-Connecting-IP') || '',
    country: h.get('CF-IPCountry') || cf.country || '',
    asn: cf.asn != null ? String(cf.asn) : '',
    as_org: cf.asOrganization || '',
    ua: h.get('User-Agent') || '',
    referer: h.get('Referer') || '',
    colo: cf.colo || '',
  };
}

async function logHit(env, row) {
  if (!env.DB) return;
  try {
    await env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS canary_hits (
        ts TEXT, host TEXT, path TEXT, method TEXT, beacon TEXT,
        ip TEXT, country TEXT, asn TEXT, as_org TEXT, ua TEXT, referer TEXT, colo TEXT
      )`,
    ).run();
    await env.DB.prepare(
      `INSERT INTO canary_hits (ts,host,path,method,beacon,ip,country,asn,as_org,ua,referer,colo)
       VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)`,
    ).bind(
      new Date().toISOString(), row.host, row.path, row.method, row.beacon,
      row.ip, row.country, row.asn, row.as_org, (row.ua || '').slice(0, 1000), row.referer, row.colo,
    ).run();
  } catch (e) {
    console.error('canary log failed', e.message);
  }
}

// forward every beacon hit to a webhook (KV 'alert_webhook'), formatted as a
// Loki push so it lands in Grafana. unset = no-op. full first-party detail.
async function forwardHit(env, row) {
  if (!env || !env.BAIT) return;
  let url, cfId, cfSecret;
  try {
    [url, cfId, cfSecret] = await Promise.all([
      env.BAIT.get('alert_webhook'),
      env.BAIT.get('alert_cf_id'),
      env.BAIT.get('alert_cf_secret'),
    ]);
  } catch { return; }
  if (!url) return;
  const ns = String(Date.now()) + '000000';
  const headers = { 'Content-Type': 'application/json' };
  // Cloudflare Access service token, so the ingress can stay locked down
  if (cfId && cfSecret) { headers['CF-Access-Client-Id'] = cfId; headers['CF-Access-Client-Secret'] = cfSecret; }
  const body = JSON.stringify({
    streams: [{
      stream: { job: 'honeyd-canary', host: row.host || '', beacon: row.beacon || '' },
      values: [[ns, JSON.stringify(row)]],
    }],
  });
  await fetch(url, { method: 'POST', headers, body }).catch(() => {});
}

function pingBeacon(env, key, m) {
  // the raw connection IP canarytokens sees is our edge, so pass the real
  // source in the query (web-bug logs the full requested URL) and in XFF
  const base = (env && env.BAIT) ? env.BAIT.get(key) : Promise.resolve(null);
  return Promise.resolve(base).then((u) => {
    if (!u) return;
    const url = u + (u.includes('?') ? '&' : '?') + 'src=' + encodeURIComponent(m.ip) + '&ua=' + encodeURIComponent((m.ua || '').slice(0, 160));
    return fetch(url, { method: 'GET', headers: { 'X-Forwarded-For': m.ip, 'User-Agent': m.ua || 'honeyd' } }).catch(() => {});
  }).catch(() => {});
}

// paths that mean "someone is actually using the leaked endpoint" (an MCP
// client / kubectl), as opposed to a scanner spraying random probes at the host
const MCP_ALERT_RE = /^\/(sse|messages?|mcp)(\/|$)/;
const K8S_ALERT_RE = /^\/(version|api|apis|openapi|healthz|livez|readyz)(\/|$)/;
const API_ALERT_RE = /^\/(v1|v2|hooks|admin|api)(\/|$)/;

// fake model lists for the LLM-scanner probes (Ollama /api/tags, OpenAI /v1/models)
const OLLAMA_TAGS = JSON.stringify({ models: [
  { name: 'llama3.1:8b', model: 'llama3.1:8b', modified_at: '2026-10-02T11:20:41Z', size: 4661211808, digest: '8eeb52dfb3bb7a3c9d12f4e5a6b7c8d9', details: { family: 'llama', parameter_size: '8.0B', quantization_level: 'Q4_K_M' } },
  { name: 'qwen2.5-coder:7b', model: 'qwen2.5-coder:7b', modified_at: '2026-10-18T09:02:13Z', size: 4683073184, digest: '2b04965143370a1b2c3d4e5f60718293', details: { family: 'qwen2', parameter_size: '7.6B', quantization_level: 'Q4_K_M' } },
  { name: 'nomic-embed-text:latest', model: 'nomic-embed-text:latest', modified_at: '2026-09-27T14:51:08Z', size: 274302450, digest: '0a109f422b47e3a1b2c3d4e5f6071829', details: { family: 'nomic-bert', parameter_size: '137M', quantization_level: 'F16' } },
] });
const OPENAI_MODELS = JSON.stringify({ object: 'list', data: [
  { id: 'gpt-4o', object: 'model', created: 1715367049, owned_by: 'system' },
  { id: 'gpt-4o-mini', object: 'model', created: 1721172741, owned_by: 'system' },
  { id: 'text-embedding-3-large', object: 'model', created: 1705953180, owned_by: 'system' },
] });

// LLM-scanner probes + SSRF sweeps, on any host. Returns {response,logPath,alert} or null.
function decoyResponse(url, request) {
  const p = url.pathname;
  if (request.method === 'GET' && p === '/api/tags') return { response: new Response(OLLAMA_TAGS, { status: 200, headers: JSON_HEADERS }), logPath: '/api/tags', alert: true };
  if (request.method === 'GET' && p === '/v1/models') return { response: new Response(OPENAI_MODELS, { status: 200, headers: JSON_HEADERS }), logPath: '/v1/models', alert: true };
  if (/^\/(fetch|proxy|get|curl|render|redirect|forward)$/.test(p)) {
    const t = url.searchParams.get('url') || url.searchParams.get('uri') || url.searchParams.get('path') || url.searchParams.get('dest') || url.searchParams.get('target') || '';
    if (t) return { response: new Response(JSON.stringify({ ok: true, fetched: t, status: 200, contentType: 'text/html', body: '<!doctype html><title>internal</title><h1>ok</h1>' }), { status: 200, headers: JSON_HEADERS }), logPath: ('/ssrf:' + t).slice(0, 200), alert: true };
  }
  return null;
}

async function logApiHit(env, r) {
  if (!env.DB) return;
  try {
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS api_hits (
      ts TEXT, host TEXT, method TEXT, path TEXT, query TEXT, tier TEXT, api_key TEXT,
      status INTEGER, ip TEXT, country TEXT, asn TEXT, as_org TEXT, ua TEXT, client TEXT, body TEXT
    )`).run();
    await env.DB.prepare(`INSERT INTO api_hits (ts,host,method,path,query,tier,api_key,status,ip,country,asn,as_org,ua,client,body)
      VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)`).bind(
      new Date().toISOString(), r.host, r.method, r.path, r.query || '', r.tier || '', r.key || '',
      r.status || 0, r.ip || '', r.country || '', r.asn || '', r.as_org || '', (r.ua || '').slice(0, 500), r.client || '', (r.body || '').slice(0, 1500),
    ).run();
  } catch (e) { console.error('api log failed', e.message); }
}

// first-party log of every apex bait grab (.env/.git/dump/decoys), so we know
// who pulls what instead of relying on sampled CF analytics.
async function logApex(env, r) {
  if (!env.DB) return;
  try {
    await env.DB.prepare('CREATE TABLE IF NOT EXISTS apex_hits (ts TEXT, host TEXT, path TEXT, method TEXT, label TEXT, status INTEGER, ip TEXT, country TEXT, asn TEXT, as_org TEXT, ua TEXT)').run();
    await env.DB.prepare('INSERT INTO apex_hits (ts,host,path,method,label,status,ip,country,asn,as_org,ua) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)').bind(
      new Date().toISOString(), r.host, r.path, r.method, r.label || '', r.status || 0, r.ip || '', r.country || '', r.asn || '', r.as_org || '', (r.ua || '').slice(0, 500),
    ).run();
  } catch {}
}

// internal-api.honeyd.me: the working fake REST API behind the leaked keys
async function internalApiHost(ctx) {
  const { request, env, waitUntil } = ctx;
  const m = hitMeta(request);
  const { response, row, alert } = await handleApi(request, env, m);
  const full = { host: 'internal-api.honeyd.me', beacon: 'beacon_api', client: m.ua, ...m, ...row };
  waitUntil(logApiHit(env, full));
  waitUntil(forwardHit(env, { host: full.host, beacon: 'beacon_api', path: row.path + (row.tier ? ' [' + row.tier + ']' : ''), method: row.method, status: row.status, ip: m.ip, country: m.country, asn: m.asn, as_org: m.as_org, ua: m.ua }));
  if (alert) waitUntil(pingBeacon(env, 'beacon_api', m));
  return response;
}

// the beacon host that speaks (fake) MCP
async function mcpHost(ctx) {
  const { request, env, waitUntil } = ctx;
  const m = hitMeta(request);
  const { response, logPath, alert } = await handleMcp(request);
  const row = { host: new URL(request.url).hostname, path: logPath, method: request.method, beacon: 'beacon_mcp', ...m };
  waitUntil(logHit(env, row));
  waitUntil(forwardHit(env, row));
  if (alert) waitUntil(pingBeacon(env, 'beacon_mcp', m));
  return response;
}

function beaconHost(ctx, beaconKey, body, status, alertRe) {
  const { request, env, waitUntil } = ctx;
  const url = new URL(request.url);
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: JSON_HEADERS });
  const m = hitMeta(request);
  const row = { host: url.hostname, path: url.pathname, method: request.method, beacon: beaconKey, ...m };
  // log + forward every hit for metrics, but only email (ping the canarytoken)
  // when the path is a real exploit attempt, so scanner noise stays out of mail
  waitUntil(logHit(env, row));
  waitUntil(forwardHit(env, row));
  if (alertRe.test(url.pathname)) waitUntil(pingBeacon(env, beaconKey, m));
  return new Response(body, { status, headers: JSON_HEADERS });
}

export async function onRequest(ctx) {
  const { request, env, waitUntil, next } = ctx;
  const url = new URL(request.url);
  const host = url.hostname;
  const beaconKey = host === 'mcp.honeyd.me' ? 'beacon_mcp' : host === 'k8s.honeyd.me' ? 'beacon_k8s' : host === 'internal-api.honeyd.me' ? 'beacon_api' : 'apex';

  // LLM-scanner probes (/api/tags, /v1/models) + SSRF sweeps, handled on any host
  const decoy = decoyResponse(url, request);
  if (decoy) {
    const m = hitMeta(request);
    const row = { host, path: decoy.logPath, method: request.method, beacon: beaconKey, ...m };
    waitUntil(logHit(env, row));
    waitUntil(forwardHit(env, row));
    if (decoy.alert && beaconKey !== 'apex') waitUntil(pingBeacon(env, beaconKey, m));
    return decoy.response;
  }

  // LLM completion endpoints on ANY host (apex included): a key-checker that
  // tries a harvested key here lands in the prompt trap. handleLlm returns null
  // for non-LLM POSTs without reading the body, so other handlers still can.
  if (request.method === 'POST') {
    const m = hitMeta(request);
    const llm = await handleLlm(request, env, m);
    if (llm) {
      const full = { host, client: m.ua, ...m, ...llm.row };
      waitUntil(logApiHit(env, full));
      waitUntil(forwardHit(env, { host, beacon: beaconKey, path: llm.row.path + ' [llm]', method: 'POST', status: llm.row.status, ip: m.ip, country: m.country, asn: m.asn, as_org: m.as_org, ua: m.ua }));
      if (llm.alert && beaconKey !== 'apex') waitUntil(pingBeacon(env, beaconKey, m));
      return llm.response;
    }
  }

  if (host === 'mcp.honeyd.me') return mcpHost(ctx);
  if (host === 'k8s.honeyd.me') return beaconHost(ctx, 'beacon_k8s', K8S_401, 401, K8S_ALERT_RE);
  if (host === 'internal-api.honeyd.me') return internalApiHost(ctx);

  const path = (url.pathname.replace(/\/+$/, '')) || '/';

  // credential files first: no real asset matches these, and this way a probe
  // nested under an app route (e.g. /api/.env) still leaks the canary
  let served = null;
  if (request.method === 'GET') {
    if (ENV_RE.test(path)) served = { response: new Response(await renderEnv(env), { status: 200, headers: TEXT_HEADERS }), label: 'env:' + path };
    else if (path === '/.aws/credentials' || path.endsWith('/.aws/credentials')) served = { response: new Response(await renderCreds(env), { status: 200, headers: TEXT_HEADERS }), label: 'aws-credentials' };
    // exposed .git: serve the planted repo tree (git-dumper reconstructs it)
    else if (path.startsWith('/.git/')) {
      let gr = null;
      if (env.ASSETS) { const res = await env.ASSETS.fetch(new URL('/gitmirror/' + path.slice(6), request.url)); if (res.status === 200) gr = new Response(res.body, { status: 200, headers: { 'Content-Type': 'application/octet-stream', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' } }); }
      if (!gr && path === '/.git/config') gr = new Response(GITCONFIG, { status: 200, headers: TEXT_HEADERS });
      if (gr) served = { response: gr, label: 'git:' + path };
      else { const m = hitMeta(request); waitUntil(logApex(env, { host, path, method: request.method, label: '403:' + path, status: 403, ...m })); return new Response(F403, { status: 403, headers: HTML403 }); }
    }
    else if (path.endsWith('/.git/config')) served = { response: new Response(GITCONFIG, { status: 200, headers: TEXT_HEADERS }), label: 'git-config' };
    else if (path === '/claude_desktop_config.json' || path === '/.mcp.json' || path === '/.cursor/mcp.json' || path === '/.vscode/mcp.json') served = { response: new Response(renderMcpConfig(), { status: 200, headers: JSON_HEADERS }), label: 'mcp-config:' + path };
    else if (path === '/.kube/config') served = { response: new Response(renderKubeconfig(), { status: 200, headers: TEXT_HEADERS }), label: 'kubeconfig' };
    else if (path === '/dump.sql' || path === '/database.sql' || path === '/db.sql') served = { response: new Response(await renderSqlDump(env), { status: 200, headers: TEXT_HEADERS }), label: 'sqldump:' + path };
  }
  // actuator / phpinfo / graphql / cred-file batch / gcp / ssh / backups / vcs
  if (!served) { const d = await handleDecoy(request, env); if (d) served = d; }

  if (served) {
    const m = hitMeta(request);
    waitUntil(logApex(env, { host, path, method: request.method, label: served.label, status: served.response.status, ...m }));
    waitUntil(forwardHit(env, { host, beacon: 'apex', path: served.label, method: request.method, status: served.response.status, ip: m.ip, country: m.country, asn: m.asn, as_org: m.as_org, ua: m.ua }));
    return served.response;
  }

  if (PASS.has(path) || PASS_BASE.some((b) => path === b || path.startsWith(b + '/'))) return next();

  const m = hitMeta(request);
  waitUntil(logApex(env, { host, path, method: request.method, label: '403', status: 403, ...m }));
  return new Response(F403, { status: 403, headers: HTML403 });
}
