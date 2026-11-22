// daily totals per event and nothing else: no ip, no ua, no cookie, body never read
const EVENTS = new Set(['download', 'meet']);
const HEADERS = { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' };

const reply = (status) => new Response(null, { status, headers: HEADERS });

export async function onRequestPost({ request, params, env }) {
  if (!EVENTS.has(params.event)) return reply(404);
  // older safari has no Sec-Fetch-Site, so fall back to Origin
  const site = request.headers.get('Sec-Fetch-Site');
  const same = site ? site === 'same-origin' : request.headers.get('Origin') === new URL(request.url).origin;
  if (!same) return reply(403);
  if (!env.DB) return reply(204); // preview deploys have no binding
  try {
    await env.DB.prepare(
      'INSERT INTO counts (day, event, n) VALUES (?1, ?2, 1) ON CONFLICT (day, event) DO UPDATE SET n = n + 1',
    ).bind(new Date().toISOString().slice(0, 10), params.event).run();
  } catch (e) {
    console.error('count failed', e.message); // over the free quota, the click still works
  }
  return reply(204);
}
