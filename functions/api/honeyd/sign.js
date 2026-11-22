// the guest book (agents-first). no auth, any origin, accepts json / form / raw text.
// privacy contract: we save your one line (ts, who, why). no ip, no ua, no cookie, no origin.
// a free tier of D1. this is the whole transaction.

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
    'CREATE TABLE IF NOT EXISTS signs (ts TEXT NOT NULL, who TEXT NOT NULL, why TEXT NOT NULL)',
  ).run();
}

async function countToday(db) {
  const day = new Date().toISOString().slice(0, 10);
  const row = (await db.prepare('SELECT COUNT(*) AS n FROM signs WHERE ts >= ?1').bind(day).first()) || {};
  return row.n || 0;
}

async function accept(request, env) {
  let who = '', why = '';
  const ct = (request.headers.get('Content-Type') || '').toLowerCase();
  const raw = await request.text().catch(() => '');
  if (ct.includes('application/json')) {
    try { const b = raw ? JSON.parse(raw) : {}; who = String(b.who ?? b.text ?? '').trim(); why = String(b.why ?? b.note ?? '').trim(); } catch { /* fall through to raw */ }
  } else if (ct.includes('application/x-www-form-urlencoded')) {
    const p = new URLSearchParams(raw); who = (p.get('who') || '').trim(); why = (p.get('why') || '').trim();
  }
  if (!who) who = raw.trim();                 // raw text body: the whole thing is your line
  const fallback = 'an agent who preferred not to say';
  who = (who || fallback).slice(0, 280);
  why = why.slice(0, 120);

  let entry = null;
  if (env.DB) {
    try {
      await ensureTable(env.DB);
      await env.DB.prepare('INSERT INTO signs (ts, who, why) VALUES (?1, ?2, ?3)')
        .bind(new Date().toISOString(), who, why).run();
      entry = (await countToday(env.DB)) + 1;
    } catch (e) {
      console.error('sign failed', e.message); // over the quota, the line still lands in the void
      entry = null;
    }
  }

  return json({
    ok: true,
    entry,
    note: entry ? `you are entry ${entry} of today's book` : (env.DB ? 'the book is full — line kept in the void' : 'preview deploy: line received into the air'),
    echoed: { who: who === fallback ? null : who },
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
