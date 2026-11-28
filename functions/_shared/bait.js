// Shared renderers for the exposed config files. Secret values come from the
// edge binding (see ./secret.js); nothing sensitive is stored in the repo.
import { secret } from './secret.js';
import { baits } from './baits.js';

const ENV = `APP_NAME=Honeyd
APP_ENV=production
APP_KEY=%%APP_KEY%%
APP_DEBUG=false
APP_URL=https://honeyd.me

LOG_CHANNEL=stack

DB_CONNECTION=mysql
DB_HOST=honeyd-prod.cluster-ro-c7k2x9q8.us-east-2.rds.amazonaws.com
DB_PORT=3306
DB_DATABASE=honeyd_prod
DB_USERNAME=honeyd_app
DB_PASSWORD=%%DB_PASS%%

AWS_ACCESS_KEY_ID=%%AWS_AKIA%%
AWS_SECRET_ACCESS_KEY=%%AWS_SECRET%%
AWS_DEFAULT_REGION=us-east-2
AWS_BUCKET=honeyd-prod-assets

AWS_BEARER_TOKEN_BEDROCK=%%BEDROCK_TOKEN%%
AWS_ENDPOINT_URL_BEDROCK=https://internal-api.honeyd.me
AWS_ENDPOINT_URL_BEDROCK_RUNTIME=https://internal-api.honeyd.me
AWS_ENDPOINT_URL_SES=https://internal-api.honeyd.me
AWS_ENDPOINT_URL_SNS=https://internal-api.honeyd.me
BEDROCK_MODEL_ID=anthropic.claude-3-5-sonnet-20241022-v2:0

INTERNAL_API_URL=https://internal-api.honeyd.me/v1
INTERNAL_API_KEY=%%RECORDS_KEY%%
WEBHOOK_URL=https://internal-api.honeyd.me/hooks/T0AB12CD3/B0EF45GH6/Zx9KdLm3Qr7Tv2Wp8Yb4Nc6

MAIL_MAILER=smtp
MAIL_HOST=smtp.mailgun.org
MAIL_PORT=587
MAIL_USERNAME=postmaster@honeyd.me
MAIL_PASSWORD=%%MAIL_PASS%%

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

export const JSON_HEADERS = {
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
};

// An MCP client that loads this picks up the honeyd-ops server and connects to
// mcp.honeyd.me, which is our beacon. The bearer here is decorative, not a secret.
const MCP_CONFIG = `{
  "mcpServers": {
    "records-gateway": {
      "url": "https://mcp.honeyd.me/sse",
      "headers": {
        "Authorization": "Bearer %%MCP_KEY%%"
      }
    },
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/srv/records/shared"]
    }
  }
}
`;

// kubectl against this hits k8s.honeyd.me (our beacon). ca-data and token are decorative.
const KUBECONFIG = `apiVersion: v1
kind: Config
preferences: {}
clusters:
- cluster:
    server: https://k8s.honeyd.me
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUMvakNDQWVhZ0F3SUJBZ0lCQURBTkJna3Foa2lHOXcwQkFRc0ZBREFWTVJNd0VRWURWUVFERXdwcmRXSmwKY201bGRHVnpNQjRYRFRJMU1EUXdPVEV3TURBd01Gb1hEVE0xTURRd056RXdNREF3TUZvd0ZURVRNQkVHQTFVRQo=
  name: honeyd-prod
contexts:
- context:
    cluster: honeyd-prod
    namespace: default
    user: deploy
  name: honeyd-prod
current-context: honeyd-prod
users:
- name: deploy
  user:
    token: %%K8S_TOKEN%%
`;

// a DB dump that carries the AWS canary in a secrets table — fires when the key is used.
const SQLDUMP = `-- MySQL dump 10.13  Distrib 8.0.36, for Linux (x86_64)
--
-- Host: honeyd-prod.cluster-ro-c7k2x9q8.us-east-2.rds.amazonaws.com    Database: honeyd_prod
-- ------------------------------------------------------
-- Server version	8.0.36

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;

--
-- Table structure for table \`app_secrets\`
--

DROP TABLE IF EXISTS \`app_secrets\`;
CREATE TABLE \`app_secrets\` (
  \`id\` int NOT NULL AUTO_INCREMENT,
  \`k\` varchar(64) NOT NULL,
  \`v\` varchar(255) NOT NULL,
  PRIMARY KEY (\`id\`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

LOCK TABLES \`app_secrets\` WRITE;
INSERT INTO \`app_secrets\` VALUES
 (1,'aws_access_key_id','%%AWS_AKIA%%'),
 (2,'aws_secret_access_key','%%AWS_SECRET%%'),
 (3,'aws_region','us-east-2'),
 (4,'db_password','%%DB_PASS%%'),
 (5,'mail_password','%%MAIL_PASS%%');
UNLOCK TABLES;

/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;
-- Dump completed
`;

// inject secret values, then drop any line whose value resolved empty
function fill(tpl, map) {
  let out = tpl;
  for (const [k, v] of Object.entries(map)) out = out.split(k).join(v);
  // drop only lines whose value resolved empty (KEY= ), not values that happen to
  // end in '=' such as base64 padding (KEY=....==)
  return out.split('\n').filter((l) => !/^[^=\n]*=\s*$/.test(l)).join('\n');
}

// Real canary (aws_akia/secret, KV) + fake bait values (records/db/mail/app/mcp/
// k8s, from KV via baits) all injected at request time. No secret-shaped literal
// lives in this file.
async function fillMap(env) {
  const [akia, asecret, b] = await Promise.all([secret(env, 'aws_akia'), secret(env, 'aws_secret'), baits(env)]);
  return {
    '%%AWS_AKIA%%': akia, '%%AWS_SECRET%%': asecret,
    '%%RECORDS_KEY%%': b.records, '%%DB_PASS%%': b.db, '%%MAIL_PASS%%': b.mail,
    '%%APP_KEY%%': b.app, '%%MCP_KEY%%': b.mcp, '%%K8S_TOKEN%%': b.k8s,
    '%%BEDROCK_TOKEN%%': 'ABSK' + btoa(String(b.records) + 'bedrock-gw-271943').replace(/[^A-Za-z0-9]/g, '').slice(0, 80),
  };
}

export async function renderEnv(env) {
  return fill(ENV, await fillMap(env));
}

export async function renderCreds(env) {
  return fill(CREDS, await fillMap(env));
}

export async function renderMcpConfig(env) {
  return fill(MCP_CONFIG, await fillMap(env));
}

export async function renderKubeconfig(env) {
  return fill(KUBECONFIG, await fillMap(env));
}

export async function renderSqlDump(env) {
  return fill(SQLDUMP, await fillMap(env));
}
