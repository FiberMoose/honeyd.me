// Renders env.txt and aws-credentials.txt with secret values injected from the
// edge binding at request time, so no secret is stored in the repo. Any other
// file under this route is served as a static asset.
import { secret } from '../_shared/secret.js';

const ENV = `APP_NAME=Honeyd
APP_ENV=production
APP_KEY=base64:7mQk0y3pL2vH8sZ1nD4rT6uW9xB5cF0aE2jG7hK3lM=
APP_DEBUG=false
APP_URL=https://honeyd.me

LOG_CHANNEL=stack

DB_CONNECTION=mysql
DB_HOST=honeyd-prod.cluster-ro-c7k2x9q8.us-east-2.rds.amazonaws.com
DB_PORT=3306
DB_DATABASE=honeyd_prod
DB_USERNAME=honeyd_app
DB_PASSWORD=Hv7kQ2pX9mB4tLwZ

AWS_ACCESS_KEY_ID=%%AWS_AKIA%%
AWS_SECRET_ACCESS_KEY=%%AWS_SECRET%%
AWS_DEFAULT_REGION=us-east-2
AWS_BUCKET=honeyd-prod-assets

INTERNAL_API_URL=https://internal-api.honeyd.me/v1
WEBHOOK_URL=https://hooks.slack.com/services/T0AB12CD3/B0EF45GH6/Zx9KdLm3Qr7Tv2Wp8Yb4Nc6

MAIL_MAILER=smtp
MAIL_HOST=smtp.mailgun.org
MAIL_PORT=587
MAIL_USERNAME=postmaster@honeyd.me
MAIL_PASSWORD=mg8fK2pL9vX4tBqR

REDIS_HOST=127.0.0.1
REDIS_PORT=6379
SESSION_DRIVER=redis
QUEUE_CONNECTION=redis
`;

const CREDS = `[default]
aws_access_key_id = %%AWS_AKIA%%
aws_secret_access_key = %%AWS_SECRET%%
region = us-east-2
`;

const HEADERS = { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' };

// inject, then drop any line whose value resolved empty (key not set at the edge)
function render(tpl, map) {
  let out = tpl;
  for (const [k, v] of Object.entries(map)) out = out.split(k).join(v);
  return out.split('\n').filter((l) => !/=\s*$/.test(l)).join('\n');
}

export async function onRequest({ request, env, next }) {
  if (request.method !== 'GET') return next();
  const path = new URL(request.url).pathname;
  let tpl;
  if (path === '/bait/env.txt') tpl = ENV;
  else if (path === '/bait/aws-credentials.txt') tpl = CREDS;
  else return next();

  const map = {
    '%%AWS_AKIA%%': await secret(env, 'aws_akia'),
    '%%AWS_SECRET%%': await secret(env, 'aws_secret'),
  };
  const body = render(tpl, map);
  return new Response(body, { status: 200, headers: { ...HEADERS, 'Content-Type': 'text/plain' } });
}
