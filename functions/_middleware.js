// Edge handler for the probe surface:
//  - serves the exposed config files (.env variants, .aws/credentials, .git/config)
//    with secret values injected from the binding at request time
//  - returns 403 for common admin/panel paths so they read as "present but
//    access-restricted" rather than absent
// Everything else passes through to the matching function or static asset.
import { renderEnv, renderCreds, GITCONFIG, TEXT_HEADERS } from './_shared/bait.js';

const ENV_PATHS = new Set(['/.env', '/.env.local', '/.env.production']);

const FORBIDDEN = [
  '/wp-login.php', '/wp-admin', '/wp-content', '/wp-includes', '/xmlrpc.php',
  '/phpmyadmin', '/pma', '/admin', '/administrator', '/manager/html',
  '/solr', '/jenkins', '/console', '/actuator', '/server-status',
  '/cgi-bin', '/config.php', '/api/v1/admin', '/owa', '/boaform', '/hnap1',
];

const F403 = '<!doctype html>\n<html><head><meta charset="utf-8"><title>403 Forbidden</title></head>\n<body>\n<h1>Forbidden</h1>\n<p>You do not have permission to access this resource.</p>\n</body></html>\n';
const HTML403 = { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' };

export async function onRequest({ request, env, next }) {
  const path = (new URL(request.url).pathname.replace(/\/+$/, '')) || '/';

  if (request.method === 'GET') {
    if (ENV_PATHS.has(path)) return new Response(await renderEnv(env), { status: 200, headers: TEXT_HEADERS });
    if (path === '/.aws/credentials') return new Response(await renderCreds(env), { status: 200, headers: TEXT_HEADERS });
    if (path === '/.git/config') return new Response(GITCONFIG, { status: 200, headers: TEXT_HEADERS });
  }

  for (const p of FORBIDDEN) {
    if (path === p || path.startsWith(p + '/')) {
      return new Response(F403, { status: 403, headers: HTML403 });
    }
  }

  return next();
}
