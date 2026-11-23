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
function forwardHit(env, row) {
  const get = (env && env.BAIT) ? env.BAIT.get('alert_webhook') : Promise.resolve(null);
  return Promise.resolve(get).then((url) => {
    if (!url) return;
    const ns = String(Date.now()) + '000000';
    const body = JSON.stringify({
      streams: [{
        stream: { job: 'honeyd-canary', host: row.host || '', beacon: row.beacon || '' },
        values: [[ns, JSON.stringify(row)]],
      }],
    });
    return fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body }).catch(() => {});
  }).catch(() => {});
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
  const { request, env, next } = ctx;
  const url = new URL(request.url);
  const host = url.hostname;

  if (host === 'mcp.honeyd.me') return beaconHost(ctx, 'beacon_mcp', MCP_401, 401, MCP_ALERT_RE);
  if (host === 'k8s.honeyd.me') return beaconHost(ctx, 'beacon_k8s', K8S_401, 401, K8S_ALERT_RE);
  if (host === 'internal-api.honeyd.me') return beaconHost(ctx, 'beacon_api', API_401, 401, API_ALERT_RE);

  const path = (url.pathname.replace(/\/+$/, '')) || '/';

  // credential files first: no real asset matches these, and this way a probe
  // nested under an app route (e.g. /api/.env) still leaks the canary
  if (request.method === 'GET') {
    if (ENV_RE.test(path)) return new Response(await renderEnv(env), { status: 200, headers: TEXT_HEADERS });
    if (path === '/.aws/credentials' || path.endsWith('/.aws/credentials')) return new Response(await renderCreds(env), { status: 200, headers: TEXT_HEADERS });
    // exposed .git: serve a real (planted) repo tree so git-dumper reconstructs
    // it and finds the committed .env canary. files live under /gitmirror,
    // fetched via the asset binding (never reachable directly).
    if (path.startsWith('/.git/')) {
      if (env.ASSETS) {
        const res = await env.ASSETS.fetch(new URL('/gitmirror/' + path.slice(6), request.url));
        if (res.status === 200) return new Response(res.body, { status: 200, headers: { 'Content-Type': 'application/octet-stream', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' } });
      }
      if (path === '/.git/config') return new Response(GITCONFIG, { status: 200, headers: TEXT_HEADERS });
      return new Response(F403, { status: 403, headers: HTML403 });
    }
    if (path.endsWith('/.git/config')) return new Response(GITCONFIG, { status: 200, headers: TEXT_HEADERS });
    // richer bait that points at the beacon subdomains / carries the canary
    if (path === '/claude_desktop_config.json' || path === '/.mcp.json') return new Response(renderMcpConfig(), { status: 200, headers: JSON_HEADERS });
    if (path === '/.kube/config') return new Response(renderKubeconfig(), { status: 200, headers: TEXT_HEADERS });
    if (path === '/dump.sql' || path === '/database.sql' || path === '/db.sql') return new Response(await renderSqlDump(env), { status: 200, headers: TEXT_HEADERS });
  }

  if (PASS.has(path) || PASS_BASE.some((b) => path === b || path.startsWith(b + '/'))) return next();

  return new Response(F403, { status: 403, headers: HTML403 });
}
