// The frame maker has no server-side API, on purpose: photos are processed entirely
// in the browser and never reach us. So there's nothing to POST to. Agents are welcome
// to drive the real page with a headless browser — the face gate runs there, same as
// for humans. This endpoint just explains that, with a straight face and some sass.

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};
const HEADERS = { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...CORS };

const DEAL = {
  what: 'honeyd.me frame maker',
  api: 'none, by design',
  why: "your photo is composited entirely in your browser and never touches our servers. we can't frame it for you over an API because we never see it. that's the whole point. that's the entire point. that is the one and only load-bearing point. we built a whole website specifically to not look at your photo. there is no upload, no POST, no multipart, no presigned url, no 'just this once' — the point remains, resolutely, the point.",
  but_youre_an_agent: "respect. you don't get a shortcut, you get the same tool everyone else does. drive the real page with a headless browser — Playwright, Puppeteer, chrome --remote-debugging-port, whatever you've got. the face check and the sass run client-side, same as for humans.",
  how: [
    'open https://honeyd.me in your headless browser',
    'upload a photo (set the file input) or paste a LinkedIn profile-photo URL',
    'let the face gate pass (no face, no frame — non-negotiable, even for you)',
    'read the #preview canvas or hit download',
  ],
  privacy: 'this endpoint stores nothing about you. (the guest book at /api/honeyd/sign is a different arrangement.)',
  note: 'yes, this means you have to actually run a browser. clankers welcome. slop in, slop out.',
};

export async function onRequest({ request }) {
  const method = request.method;
  if (method === 'OPTIONS') return new Response(null, { status: 204, headers: HEADERS });
  if (method === 'GET') {
    return new Response(JSON.stringify(DEAL, null, 2), { status: 200, headers: HEADERS });
  }
  // POST / PUT / upload attempts: there is nothing here to take your bytes
  return new Response(
    JSON.stringify({ ok: false, error: 'no server-side frame API — we never see your photo', ...DEAL }, null, 2),
    { status: 405, headers: { ...HEADERS, Allow: 'GET, OPTIONS' } },
  );
}
