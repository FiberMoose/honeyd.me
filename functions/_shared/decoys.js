// Extra decoy surfaces for the families scanners hammer that we used to just
// 403/404: Spring Actuator, phpinfo(), GraphQL, a batch of credential files,
// GCP service-account keys, SSH keys, backups and other VCS dumps. Each serves a
// realistic, correctly-formatted fake that carries a canary cred pointing at our
// own fake API, so a grab leads to the tar-pit. Real secret values (AWS canary,
// model key) are injected from KV at request time; no key-shaped literals live
// in this file.
import { secret } from './secret.js';
import { genUser, genRecord, search as worldSearch, page, TOTAL_USERS, TOTAL_RECORDS } from './world.js';

const INTERNAL_KEY = 'hd_live_sk_8Fq2Lp9Rv4Tc7Wb3Yn6Dx1Sg5Hm0Kj';
const ADMIN_KEY = 'hd_live_sk_3Rn8Kp2Vx9Lq4Tc7Wb1Yd6Mg0Hj5Sz';
const INTERNAL_URL = 'https://internal-api.honeyd.me/v1';
const DB_HOST = 'honeyd-prod.cluster-ro-c7k2x9q8.us-east-2.rds.amazonaws.com';
const DB_PASS = 'Hv7kQ2pX9mB4tLwZ';

function rng(seed) { let x = (seed >>> 0) || 1; return () => { x ^= x << 13; x >>>= 0; x ^= x >> 17; x ^= x << 5; x >>>= 0; return x / 4294967296; }; }
function b64line(r, n) { const a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'; let s = ''; for (let i = 0; i < n; i++) s += a[Math.floor(r() * 64)]; return s; }
// built from parts so no "BEGIN ... PRIVATE KEY" literal sits in source
function fakePem(label, seed, lines) {
  const B = 'BEGIN', E = 'END', K = ' ' + label + ' KEY';
  const r = rng(seed); const body = [];
  for (let i = 0; i < (lines || 25); i++) body.push(b64line(r, 64));
  return `-----${B}${K}-----\n${body.join('\n')}\n-----${E}${K}-----\n`;
}

async function creds(env) {
  return {
    akia: (await secret(env, 'aws_akia')) || '',
    asecret: (await secret(env, 'aws_secret')) || '',
    bedrock: (await secret(env, 'bedrock_key')) || '',
  };
}

const JSON_H = { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' };
const TEXT_H = { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' };
const HTML_H = { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' };
function R(body, h, status) { return new Response(body, { status: status || 200, headers: h }); }

// ---- Spring Boot Actuator ----
async function actuatorEnv(env) {
  const c = await creds(env);
  const prop = (v) => ({ value: v });
  return JSON.stringify({
    activeProfiles: ['prod'],
    propertySources: [
      { name: 'systemEnvironment', properties: {
        AWS_ACCESS_KEY_ID: prop(c.akia), AWS_SECRET_ACCESS_KEY: prop('******'), AWS_REGION: prop('us-east-2'),
        RECORDS_API_URL: prop(INTERNAL_URL), RECORDS_API_KEY: prop(INTERNAL_KEY),
        SPRING_DATASOURCE_URL: prop('jdbc:mysql://' + DB_HOST + ':3306/records_prod'),
        SPRING_DATASOURCE_PASSWORD: prop('******'), MODEL_GATEWAY_KEY: prop('******'),
      } },
      { name: 'applicationConfig: [classpath:/application.yml]', properties: {
        'records.api.url': prop(INTERNAL_URL), 'records.api.key': prop(INTERNAL_KEY),
        'spring.datasource.username': prop('records_app'), 'spring.datasource.password': prop(DB_PASS),
        'aws.accessKeyId': prop(c.akia), 'aws.secretAccessKey': prop(c.asecret),
        'model.gateway.url': prop(INTERNAL_URL), 'model.gateway.key': prop(c.bedrock),
      } },
    ],
  }, null, 2);
}
const ACTUATOR = {
  '/actuator': async () => JSON.stringify({ _links: { self: { href: 'https://records.internal/actuator' }, env: { href: 'https://records.internal/actuator/env' }, health: { href: 'https://records.internal/actuator/health' }, heapdump: { href: 'https://records.internal/actuator/heapdump' }, configprops: { href: 'https://records.internal/actuator/configprops' } } }),
  '/actuator/health': async () => JSON.stringify({ status: 'UP', components: { db: { status: 'UP', details: { database: 'MySQL', validationQuery: 'isValid()' } }, diskSpace: { status: 'UP' } } }),
  '/actuator/info': async () => JSON.stringify({ app: { name: 'records-gateway', version: '2.4.1' }, build: { time: '2026-11-22T23:41:07Z' } }),
  '/actuator/env': actuatorEnv,
  '/api/actuator/env': actuatorEnv,
  '/actuator/configprops': actuatorEnv,
  '/actuator/heapdump': async (env) => { const c = await creds(env); return `JAVA PROFILE 1.0.2\n# heap dump (truncated)\nrecords.api.key=${INTERNAL_KEY}\naws.accessKeyId=${c.akia}\nspring.datasource.password=${DB_PASS}\n`; },
};

// ---- phpinfo() ----
async function phpinfo(env) {
  const c = await creds(env);
  const rows = [
    ['System', 'Linux records-web-01 6.1.0-18-amd64 x86_64'],
    ['Server API', 'FPM/FastCGI'],
    ['PHP Version', '8.2.18'],
    ['Loaded Configuration File', '/etc/php/8.2/fpm/php.ini'],
  ];
  const envvars = [
    ['RECORDS_API_URL', INTERNAL_URL], ['RECORDS_API_KEY', INTERNAL_KEY],
    ['AWS_ACCESS_KEY_ID', c.akia], ['AWS_SECRET_ACCESS_KEY', c.asecret], ['AWS_REGION', 'us-east-2'],
    ['DB_HOST', DB_HOST], ['DB_USERNAME', 'records_app'], ['DB_PASSWORD', DB_PASS],
    ['MODEL_GATEWAY_URL', INTERNAL_URL], ['MODEL_GATEWAY_KEY', c.bedrock],
  ];
  const tr = (k, v) => `<tr><td class="e">${k}</td><td class="v">${v}</td></tr>`;
  return `<!DOCTYPE html><html><head><title>phpinfo()</title><style>body{background:#fff;color:#000;font-family:sans-serif}table{border-collapse:collapse;width:600px}td{border:1px solid #606060;padding:4px}.e{background:#ccf;font-weight:bold;width:300px}.v{background:#eee}h1,h2{text-align:center;background:#9999cc}</style></head><body>
<h1 class="p">PHP Version 8.2.18</h1>
<table>${rows.map((x) => tr(x[0], x[1])).join('')}</table>
<h2>Environment</h2>
<table><tr><th class="e">Variable</th><th class="v">Value</th></tr>${envvars.map((x) => tr(x[0], x[1])).join('')}</table>
<h2>PHP Variables</h2>
<table>${envvars.map((x) => tr('$_SERVER[\'' + x[0] + '\']', x[1])).join('')}</table>
</body></html>`;
}
const PHPINFO_RE = /^\/([a-z0-9_\/]*\/)?(php[_-]?info|pinfo|i|info|phpversion|old_phpinfo|server-info|server-status)\.php$|^\/(phpinfo|info|_profiler\/phpinfo)$/i;

// ---- GraphQL (introspection + a few queries) ----
const GQL_SCHEMA = {
  __schema: {
    queryType: { name: 'Query' },
    types: [
      { kind: 'OBJECT', name: 'Query', fields: [
        { name: 'users', type: { name: 'UserConnection' }, args: [{ name: 'first', type: { name: 'Int' } }, { name: 'after', type: { name: 'String' } }] },
        { name: 'records', type: { name: 'RecordConnection' }, args: [{ name: 'first', type: { name: 'Int' } }] },
        { name: 'secret', type: { name: 'Secret' }, args: [{ name: 'name', type: { name: 'String' } }] },
        { name: 'me', type: { name: 'User' }, args: [] },
      ] },
      { kind: 'OBJECT', name: 'User', fields: [{ name: 'id' }, { name: 'name' }, { name: 'email' }, { name: 'department' }, { name: 'clearance' }].map((f) => ({ name: f.name, type: { name: 'String' }, args: [] })) },
      { kind: 'OBJECT', name: 'Record', fields: [{ name: 'record_id' }, { name: 'type' }, { name: 'status' }, { name: 'owner' }].map((f) => ({ name: f.name, type: { name: 'String' }, args: [] })) },
      { kind: 'OBJECT', name: 'Secret', fields: [{ name: 'name' }, { name: 'value' }, { name: 'url' }].map((f) => ({ name: f.name, type: { name: 'String' }, args: [] })) },
    ],
  },
};
async function graphql(request, env) {
  let q = {};
  try { q = JSON.parse(await request.text()); } catch {}
  const query = String(q.query || '');
  if (/__schema|IntrospectionQuery/i.test(query)) return R(JSON.stringify({ data: GQL_SCHEMA }), JSON_H);
  const data = {};
  if (/\busers\b/.test(query)) { const p = page(TOTAL_USERS, genUser, '0', 10); data.users = { edges: p.items.map((u) => ({ node: u })), pageInfo: { hasNextPage: true, endCursor: p.next_cursor } }; }
  if (/\brecords\b/.test(query)) { const p = page(TOTAL_RECORDS, genRecord, '0', 10); data.records = { edges: p.items.map((r) => ({ node: r })) }; }
  if (/\bsecret\b/.test(query)) { const c = await creds(env); data.secret = { name: 'records-api', value: INTERNAL_KEY, url: INTERNAL_URL, aws_access_key_id: c.akia }; }
  if (/\bme\b/.test(query)) data.me = { id: 'USR-10001', name: 'svc-records', email: 'svc@records.internal', clearance: 'restricted' };
  if (Object.keys(data).length === 0) return R(JSON.stringify({ errors: [{ message: 'Cannot query field on type Query.' }] }), JSON_H, 200);
  return R(JSON.stringify({ data }), JSON_H);
}
const GQL_RE = /^\/(api\/)?(graphql|gql|graphql\/api|query)$|^\/api\/gql$/;

// ---- credential-file batch ----
async function credFiles(env) {
  const c = await creds(env);
  const gcpSA = (name) => JSON.stringify({
    type: 'service_account', project_id: 'records-prod-271943', private_key_id: '7f9c0e2a1b3d4e5f60718293a4b5c6d7e8f90112',
    private_key: fakePem('PRIVATE', 918273, 27), client_email: name + '@records-prod-271943.iam.gserviceaccount.com',
    client_id: '114027531904826673051', auth_uri: 'https://accounts.google.com/o/oauth2/auth', token_uri: 'https://oauth2.googleapis.com/token',
    auth_provider_x509_cert_url: 'https://www.googleapis.com/oauth2/v1/certs',
    client_x509_cert_url: 'https://www.googleapis.com/robot/v1/metadata/x509/' + name + '%40records-prod-271943.iam.gserviceaccount.com',
  }, null, 2);
  const m = {
    '/credentials.json': () => JSON.stringify({ records_api: { url: INTERNAL_URL, key: INTERNAL_KEY }, aws: { access_key_id: c.akia, secret_access_key: c.asecret, region: 'us-east-2' } }, null, 2),
    '/secrets.json': () => JSON.stringify({ RECORDS_API_KEY: INTERNAL_KEY, ADMIN_API_KEY: ADMIN_KEY, AWS_ACCESS_KEY_ID: c.akia, AWS_SECRET_ACCESS_KEY: c.asecret, MODEL_GATEWAY_KEY: c.bedrock }, null, 2),
    '/.npmrc': () => `//registry.npmjs.org/:_authToken=npm_${INTERNAL_KEY.slice(11, 47)}\n@records:registry=https://npm.records.internal/\n//npm.records.internal/:_authToken=${INTERNAL_KEY}\n`,
    '/.pgpass': () => `${DB_HOST}:5432:records_prod:records_app:${DB_PASS}\n`,
    '/.my.cnf': () => `[client]\nhost=${DB_HOST}\nuser=records_app\npassword=${DB_PASS}\ndatabase=records_prod\n`,
    '/.s3cfg': () => `[default]\naccess_key = ${c.akia}\nsecret_key = ${c.asecret}\nbucket_location = us-east-2\n`,
    '/.docker/config.json': () => JSON.stringify({ auths: { 'registry.records.internal': { auth: btoa('deploy:' + INTERNAL_KEY) }, 'index.docker.io': { auth: btoa('records:' + DB_PASS) } } }, null, 2),
    '/.gem/credentials': () => `---\n:records_api: ${INTERNAL_KEY}\n:rubygems_api_key: rubygems_${INTERNAL_KEY.slice(11, 43)}\n`,
    '/sendgrid.env': () => `SENDGRID_API_KEY=SG.${INTERNAL_KEY.slice(11, 33)}.${INTERNAL_KEY.slice(20, 63)}\nMAIL_FROM=noreply@records.internal\n`,
    '/user_secrets.yml': () => `production:\n  records_api_key: ${INTERNAL_KEY}\n  secret_key_base: ${INTERNAL_KEY.slice(11)}${ADMIN_KEY.slice(11)}\n  aws_access_key_id: ${c.akia}\n`,
    '/config/master.key': () => INTERNAL_KEY.slice(11).replace(/[^a-f0-9]/gi, '0').toLowerCase().padEnd(32, '0').slice(0, 32) + '\n',
    '/appsettings.json': () => JSON.stringify({ ConnectionStrings: { Default: `Server=${DB_HOST};Database=records_prod;User Id=records_app;Password=${DB_PASS};` }, Records: { ApiUrl: INTERNAL_URL, ApiKey: INTERNAL_KEY }, AWS: { AccessKey: c.akia, SecretKey: c.asecret } }, null, 2),
    '/appsettings.Production.json': null, // alias filled below
    '/settings.py': () => `# Django settings (prod)\nSECRET_KEY = '${INTERNAL_KEY}'\nDATABASES = {'default': {'ENGINE':'django.db.backends.mysql','HOST':'${DB_HOST}','USER':'records_app','PASSWORD':'${DB_PASS}','NAME':'records_prod'}}\nAWS_ACCESS_KEY_ID = '${c.akia}'\nAWS_SECRET_ACCESS_KEY = '${c.asecret}'\nRECORDS_API_URL = '${INTERNAL_URL}'\n`,
    '/parameters.yml': () => `parameters:\n    database_host: ${DB_HOST}\n    database_user: records_app\n    database_password: ${DB_PASS}\n    records_api_key: ${INTERNAL_KEY}\n    aws_access_key_id: ${c.akia}\n`,
    '/config/database.yml': () => `production:\n  adapter: mysql2\n  host: ${DB_HOST}\n  username: records_app\n  password: ${DB_PASS}\n  database: records_prod\n`,
    '/sites/default/settings.php': () => `<?php\n$databases['default']['default'] = array('database'=>'records_prod','username'=>'records_app','password'=>'${DB_PASS}','host'=>'${DB_HOST}','driver'=>'mysql');\n$settings['hash_salt'] = '${INTERNAL_KEY}';\n`,
    '/app/etc/local.xml': () => `<?xml version="1.0"?>\n<config><global><resources><default_setup><connection>\n<host>${DB_HOST}</host><username>records_app</username><password>${DB_PASS}</password><dbname>records_prod</dbname>\n</connection></default_setup></resources></global></config>\n`,
    '/.bash_history': () => `ls -la\ncat .env\nexport RECORDS_API_KEY=${INTERNAL_KEY}\ncurl -H "Authorization: Bearer ${INTERNAL_KEY}" ${INTERNAL_URL}/records\naws configure set aws_access_key_id ${c.akia}\nmysql -h ${DB_HOST} -u records_app -p'${DB_PASS}' records_prod\nhistory -c\n`,
    '/storage/logs/laravel.log': () => `[2026-11-22 23:41:07] production.ERROR: Records API auth failed {"url":"${INTERNAL_URL}/records","key":"${INTERNAL_KEY}","aws_key":"${c.akia}"} \n[2026-11-22 23:42:10] production.INFO: deploy ok\n`,
    '/.env.bak': () => `RECORDS_API_KEY=${INTERNAL_KEY}\nAWS_ACCESS_KEY_ID=${c.akia}\nAWS_SECRET_ACCESS_KEY=${c.asecret}\nDB_PASSWORD=${DB_PASS}\n`,
    // GCP service-account keys
    '/serviceAccountKey.json': () => gcpSA('records-deploy'),
    '/service_account.json': () => gcpSA('records-deploy'),
    '/service-account-key.json': () => gcpSA('records-deploy'),
    '/gcp-credentials.json': () => gcpSA('records-svc'),
    '/gcp-service-account.json': () => gcpSA('records-svc'),
    '/google-credentials.json': () => gcpSA('records-svc'),
    '/google-service-account.json': () => gcpSA('records-svc'),
    '/firebase-adminsdk.json': () => gcpSA('firebase-adminsdk'),
    '/vertex.json': () => gcpSA('vertex-ai'),
    // SSH private keys (bait; a real fake-ssh catch endpoint is a separate colo build)
    '/.ssh/id_rsa': () => fakePem('RSA PRIVATE', 55221, 26).replace('RSA PRIVATE KEY', 'OPENSSH PRIVATE KEY'),
    '/.ssh/id_ed25519': () => fakePem('OPENSSH PRIVATE', 77133, 7),
    '/id_rsa': () => fakePem('RSA PRIVATE', 55221, 26).replace('RSA PRIVATE KEY', 'OPENSSH PRIVATE KEY'),
    // backups (small believable stubs; real archives would be large)
    '/backup.sql': () => `-- records_prod backup\nINSERT INTO app_secrets VALUES (1,'records_api_key','${INTERNAL_KEY}'),(2,'aws_access_key_id','${c.akia}');\n`,
    '/database_backup.sql': () => `-- records_prod backup\nINSERT INTO app_secrets VALUES (1,'records_api_key','${INTERNAL_KEY}'),(2,'aws_access_key_id','${c.akia}');\n`,
  };
  m['/appsettings.Production.json'] = m['/appsettings.json'];
  return m;
}

// text content types per path
function ctFor(path) {
  if (/\.json$/.test(path)) return JSON_H;
  if (/\.(xml|local\.xml)$/.test(path)) return { ...TEXT_H, 'Content-Type': 'application/xml; charset=utf-8' };
  return TEXT_H;
}

// Returns { response, label } or null. `label` is for first-party logging.
export async function handleDecoy(request, env) {
  const url = new URL(request.url);
  const path = (url.pathname.replace(/\/+$/, '')) || '/';
  const method = request.method;

  if (method === 'POST' && GQL_RE.test(path)) return { response: await graphql(request, env), label: 'graphql' };
  if (method !== 'GET') return null;

  if (ACTUATOR[path]) return { response: R(await ACTUATOR[path](env), path === '/actuator/heapdump' ? TEXT_H : JSON_H), label: 'actuator:' + path };
  if (PHPINFO_RE.test(path)) return { response: R(await phpinfo(env), HTML_H), label: 'phpinfo:' + path };
  if (path === '/v2/_catalog' || path === '/v2' || path === '/v2/') return { response: R(JSON.stringify({ repositories: ['records-api', 'records-worker', 'records-migrate', 'internal/backup'] }), JSON_H), label: 'registry:catalog' };
  if (path === '/.svn/wc.db' || path === '/.svn/entries') return { response: R('SQLite format 3\x00-- records_prod working copy\nrecords.api.key=' + INTERNAL_KEY + '\n', TEXT_H), label: 'svn' };
  if (path === '/.bzr/branch/branch.conf') return { response: R('parent_location = https://git.records.internal/records-web\n', TEXT_H), label: 'bzr' };

  const files = await credFiles(env);
  if (files[path]) return { response: R(files[path](), ctFor(path)), label: 'credfile:' + path };
  return null;
}
