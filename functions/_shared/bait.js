// Shared renderers for the exposed config files. Secret values come from the
// edge binding (see ./secret.js); nothing sensitive is stored in the repo.
import { secret } from './secret.js';

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

export const GITCONFIG = `[core]
\trepositoryformatversion = 0
\tfilemode = false
\tbare = false
\tlogallrefupdates = true
\tsymlinks = false
\tignorecase = true
[remote "origin"]
\turl = https://git.honeyd.me/ops/honeyd-web.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
[user]
\tname = deploy
\temail = deploy@honeyd.me
`;

export const TEXT_HEADERS = {
  'Content-Type': 'text/plain; charset=utf-8',
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
};

// inject secret values, then drop any line whose value resolved empty
function fill(tpl, map) {
  let out = tpl;
  for (const [k, v] of Object.entries(map)) out = out.split(k).join(v);
  return out.split('\n').filter((l) => !/=\s*$/.test(l)).join('\n');
}

async function awsMap(env) {
  return {
    '%%AWS_AKIA%%': await secret(env, 'aws_akia'),
    '%%AWS_SECRET%%': await secret(env, 'aws_secret'),
  };
}

export async function renderEnv(env) {
  return fill(ENV, await awsMap(env));
}

export async function renderCreds(env) {
  return fill(CREDS, await awsMap(env));
}
