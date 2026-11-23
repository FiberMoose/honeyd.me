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
    "honeyd-ops": {
      "url": "https://mcp.honeyd.me/sse",
      "headers": {
        "Authorization": "Bearer hd_mcp_8Kq2Lp9Rv4Tc7Wb3Yn6Dx1Sg"
      }
    },
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/srv/honeyd/shared"]
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
    token: eyJhbGciOiJSUzI1NiIsImtpZCI6Imhkc3ZjIn0.hd_k8s_Qn7Vb2Mx9Lp4Tc8Wk.Rg3Yd6Sz1Fv0
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
 (4,'db_password','Hv7kQ2pX9mB4tLwZ'),
 (5,'mail_password','mg8fK2pL9vX4tBqR');
UNLOCK TABLES;

/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;
-- Dump completed
`;

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

export function renderMcpConfig() {
  return MCP_CONFIG;
}

export function renderKubeconfig() {
  return KUBECONFIG;
}

export async function renderSqlDump(env) {
  return fill(SQLDUMP, await awsMap(env));
}
