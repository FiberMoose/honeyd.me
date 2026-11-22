// Returns 403 for common admin/panel/system probe paths so they read as
// "present but access-restricted" instead of absent. Everything else passes
// through to the matching function or static asset.
const FORBIDDEN = [
  '/wp-login.php', '/wp-admin', '/wp-content', '/wp-includes', '/xmlrpc.php',
  '/phpmyadmin', '/pma', '/admin', '/administrator', '/manager/html',
  '/solr', '/jenkins', '/console', '/actuator', '/server-status',
  '/cgi-bin', '/config.php', '/api/v1/admin', '/owa', '/boaform', '/hnap1',
];

const BODY = '<!doctype html>\n<html><head><meta charset="utf-8"><title>403 Forbidden</title></head>\n<body>\n<h1>Forbidden</h1>\n<p>You do not have permission to access this resource.</p>\n</body></html>\n';
const HEADERS = { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' };

export async function onRequest({ request, next }) {
  const path = (new URL(request.url).pathname.replace(/\/+$/, '')) || '/';
  for (const p of FORBIDDEN) {
    if (path === p || path.startsWith(p + '/')) {
      return new Response(BODY, { status: 403, headers: HEADERS });
    }
  }
  return next();
}
