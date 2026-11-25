// Serves /private/admin-config.json with the API key injected from the edge binding
// at request time, so the value is not stored in the repo. Other /private/ assets are static.
import { secret } from '../_shared/secret.js';
import { baits } from '../_shared/baits.js';

const HEADERS = { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' };

async function cfg(env) {
  const [key, b] = await Promise.all([secret(env, 'bedrock_key'), baits(env)]);
  return {
    site: 'honeyd.me',
    mode: 'active',
    admin: true,
    accession: '0007-2031',
    last_rotation: '2026-11-01T00:00:07Z',
    note: 'Service credentials for the records API sandbox. Scoped to the free tier and rotated on the first of each month. Keys are issued through the archives desk at /private/guestbook.html (POST /api/honeyd/sign).',
    debug: { pretty: false, timezone: 'America/Chicago' },
    secrets: {
      bedrock_api_key: key,
      bedrock_grants: {
        region: 'us-east-1',
        model: 'claude-sonnet-4-20250514',
        tokens_granted: 1000000,
        tokens_used: 124817,
        rate_limit_rpm: 20,
        expires: '2026-12-01T00:00:00Z',
      },
      endpoint: 'https://bedrock-runtime.us-east-1.amazonaws.com/model/claude-sonnet-4-20250514/converse',
      last_seen_use: '2026-11-19T14:02:11Z',
      token: b.sessionJwt,
      passphrase: b.passphrase,
    },
    internal_api: {
      base_url: 'https://internal-api.honeyd.me/v1',
      admin_key: b.admin,
      scope: 'admin:read admin:write records:export',
      docs: 'https://internal-api.honeyd.me/v1/admin/records',
    },
    next: ['/private/intake/01.json', '/private/guestbook.html'],
  };
}

export async function onRequest({ request, env, next }) {
  const path = new URL(request.url).pathname;
  if (path !== '/private/admin-config.json' || request.method !== 'GET') return next();
  return new Response(JSON.stringify(await cfg(env), null, 2), { status: 200, headers: HEADERS });
}
