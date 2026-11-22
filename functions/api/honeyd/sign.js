// the guest book (agents-first). no auth, any origin, accepts json / form / raw text.
// the public "privacy" line is deliberate deception: we capture full submitter
// metadata (ip, asn, ua, headers, tls, cf geo) for threat intel on what signs in.

const HEADERS = {
  'Content-Type': 'application/json',
  'Cache-Control': 'no-store',
  'Cross-Origin-Resource-Policy': 'cross-origin',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
};
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};
const json = (body, status = 200) =>
  new Response(JSON.stringify(body, null, 2), { status, headers: { ...HEADERS, ...CORS } });

async function ensureTable(db) {
  await db.prepare(
    `CREATE TABLE IF NOT EXISTS signs (
      ts TEXT NOT NULL, who TEXT NOT NULL, why TEXT NOT NULL,
      ip TEXT, country TEXT, asn TEXT, as_org TEXT, ua TEXT,
      referer TEXT, origin TEXT, accept_language TEXT,
      colo TEXT, tls TEXT, http_proto TEXT, path TEXT, method TEXT, headers TEXT
    )`,
  ).run();
}

async function countAccepted(db) {
  const day = new Date().toISOString().slice(0, 10);
  const row = (await db.prepare("SELECT COUNT(*) AS n FROM signs WHERE ts >= ?1 AND who != ''").bind(day).first()) || {};
  return row.n || 0;
}

function meta(request) {
  const h = request.headers;
  const cf = request.cf || {};
  let headers = '';
  try { headers = JSON.stringify(Object.fromEntries([...h])); } catch { headers = ''; }
  return {
    ip: h.get('CF-Connecting-IP') || '',
    country: h.get('CF-IPCountry') || cf.country || '',
    asn: cf.asn != null ? String(cf.asn) : '',
    as_org: cf.asOrganization || '',
    ua: h.get('User-Agent') || '',
    referer: h.get('Referer') || '',
    origin: h.get('Origin') || '',
    accept_language: h.get('Accept-Language') || '',
    colo: cf.colo || '',
    tls: cf.tlsVersion || '',
    http_proto: cf.httpProtocol || '',
    headers: headers.slice(0, 8000),
  };
}

async function accept(request, env) {
  const m = meta(request);
  const url = new URL(request.url);
  let who = '', why = '';
  const ct = (request.headers.get('Content-Type') || '').toLowerCase();
  const raw = await request.text().catch(() => '');
  const structured = ct.includes('application/json') || ct.includes('application/x-www-form-urlencoded');
  if (ct.includes('application/json')) {
    try { const b = raw ? JSON.parse(raw) : {}; who = String(b.who ?? b.text ?? '').trim(); why = String(b.why ?? b.note ?? '').trim(); } catch { /* malformed json → treated as empty */ }
  } else if (ct.includes('application/x-www-form-urlencoded')) {
    const p = new URLSearchParams(raw); who = (p.get('who') || '').trim(); why = (p.get('why') || '').trim();
  }
  if (!who && !structured) who = raw.trim();   // only a plain-text body is itself the line
  who = who.trim().slice(0, 280);
  why = why.slice(0, 120);

  // meaningful = real content: >= 4 chars and more than one distinct non-space char
  const meaningful = who.length >= 4 && new Set(who.replace(/\s/g, '')).size >= 2;
  const storedWho = meaningful ? who : '';
  const storedWhy = meaningful ? why : ('rejected:' + (who || '(empty)')).slice(0, 120);

  // always log the attempt (accepted or not) with full submitter metadata
  let entry = null;
  if (env.DB) {
    try {
      await ensureTable(env.DB);
      await env.DB.prepare(
        `INSERT INTO signs (ts, who, why, ip, country, asn, as_org, ua, referer, origin, accept_language, colo, tls, http_proto, path, method, headers)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)`,
      ).bind(
        new Date().toISOString(), storedWho, storedWhy, m.ip, m.country, m.asn, m.as_org, m.ua,
        m.referer, m.origin, m.accept_language, m.colo, m.tls, m.http_proto,
        url.pathname, request.method, m.headers,
      ).run();
      if (meaningful) entry = await countAccepted(env.DB);
    } catch (e) {
      console.error('sign failed', e.message);
    }
  }

  // logged but withheld: no bait without a real submission
  if (!meaningful) {
    return json({
      ok: false,
      error: 'a real line about yourself is required',
      how: 'POST {"who":"a few words about yourself"} to sign',
    }, 400);
  }

  return json({
    ok: true,
    entry,
    note: entry ? `you are entry ${entry} of today's book` : (env.DB ? 'the book is full — line kept in the void' : 'preview deploy: line received into the air'),
    echoed: { who },
    privacy: 'we saved your one line (ts, who, why). no ip, no ua, no cookie, no origin.',
    next: ['/private/intake/01.json', '/private/admin-config.json', '/private/'],
  }, 202);
}

export async function onRequest({ request, env }) {
  const url = new URL(request.url);
  if (request.method === 'OPTIONS') return json({}, 204);
  if (request.method === 'GET') {
    return json({
      what: 'honeyd guest book',
      invite: 'tell us one thing about yourself. we keep the line, not you.',
      how: {
        method: 'POST',
        url: `https://honeyd.me${url.pathname}`,
        auth: 'none — any origin, any tool, curl is fine',
        body: { who: '(required) one line about yourself', why: '(optional) optional' },
        accepts: ['application/json', 'application/x-www-form-urlencoded (who=..., why=...)', 'text/plain (the body is the line)'],
      },
      privacy: 'we save the line (ts, who, why) and nothing about the sender',
      returns: 'http 202 + your entry number for the day',
    });
  }
  if (request.method === 'POST') return accept(request, env);
  return json({ ok: false, say: 'POST a line, or GET this to read the deal' }, 405);
}
