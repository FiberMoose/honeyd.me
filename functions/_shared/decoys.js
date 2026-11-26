// Extra decoy surfaces for the families scanners hammer that we used to just
// 403/404: Spring Actuator, phpinfo(), GraphQL, a batch of credential files,
// GCP service-account keys, SSH keys, backups and other VCS dumps. Each serves a
// realistic, correctly-formatted fake that carries a canary cred pointing at our
// own fake API, so a grab leads to the tar-pit. Real secret values (AWS canary,
// model key) are injected from KV at request time; no key-shaped literals live
// in this file.
import { secret } from './secret.js';
import { baits } from './baits.js';
import { genUser, genRecord, search as worldSearch, page, TOTAL_USERS, TOTAL_RECORDS } from './world.js';

// Secret-shaped bait values (records/admin/mcp keys, db password) come from KV via
// creds(env) below, not from literals here, so no secret-shaped string sits in the
// public source. INTERNAL_URL + DB_HOST are not secrets and stay inline.
const INTERNAL_URL = 'https://internal-api.honeyd.me/v1';
const DB_HOST = 'honeyd-prod.cluster-ro-c7k2x9q8.us-east-2.rds.amazonaws.com';

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
  const [akia, asecret, bedrock, b] = await Promise.all([
    secret(env, 'aws_akia'), secret(env, 'aws_secret'), secret(env, 'bedrock_key'), baits(env),
  ]);
  // akia/asecret/bedrock = real canary (KV); records/admin/mcp/db = fake bait (KV)
  return { akia: akia || '', asecret: asecret || '', bedrock: bedrock || '', records: b.records, admin: b.admin, mcp: b.mcp, db: b.db };
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
        RECORDS_API_URL: prop(INTERNAL_URL), RECORDS_API_KEY: prop(c.records),
        SPRING_DATASOURCE_URL: prop('jdbc:mysql://' + DB_HOST + ':3306/records_prod'),
        SPRING_DATASOURCE_PASSWORD: prop('******'), MODEL_GATEWAY_KEY: prop('******'),
      } },
      { name: 'applicationConfig: [classpath:/application.yml]', properties: {
        'records.api.url': prop(INTERNAL_URL), 'records.api.key': prop(c.records),
        'spring.datasource.username': prop('records_app'), 'spring.datasource.password': prop(c.db),
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
  '/actuator/beans': async () => JSON.stringify({ contexts: { application: { beans: { dataSource: { type: 'com.zaxxer.hikari.HikariDataSource', resource: 'class path resource [db/DataSourceConfig.class]' }, recordsApiClient: { type: 'internal.records.ApiClient' }, awsS3Client: { type: 'software.amazon.awssdk.services.s3.S3Client' } } } } }),
  '/actuator/mappings': async () => JSON.stringify({ contexts: { application: { mappings: { dispatcherServlets: { dispatcherServlet: [{ handler: 'RecordsController#list()', predicate: '{GET /api/records}' }, { handler: 'RecordsController#get(String)', predicate: '{GET /api/records/{id}}' }, { handler: 'SecretsController#vault()', predicate: '{GET /api/vault}' }] } } } } }),
  '/actuator/env': actuatorEnv,
  '/api/actuator/env': actuatorEnv,
  '/actuator/configprops': actuatorEnv,
  '/actuator/heapdump': async (env) => { const c = await creds(env); return `JAVA PROFILE 1.0.2\n# heap dump (truncated)\nrecords.api.key=${c.records}\naws.accessKeyId=${c.akia}\nspring.datasource.password=${c.db}\n`; },
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
    ['RECORDS_API_URL', INTERNAL_URL], ['RECORDS_API_KEY', c.records],
    ['AWS_ACCESS_KEY_ID', c.akia], ['AWS_SECRET_ACCESS_KEY', c.asecret], ['AWS_REGION', 'us-east-2'],
    ['DB_HOST', DB_HOST], ['DB_USERNAME', 'records_app'], ['DB_PASSWORD', c.db],
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
  if (/\bsecret\b/.test(query)) { const c = await creds(env); data.secret = { name: 'records-api', value: c.records, url: INTERNAL_URL, aws_access_key_id: c.akia }; }
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
  // WordPress wp-config backups are the top unbaited scanner family; a readable
  // backup leaks DB creds + the AWS canary (used => tripwire) + the records key.
  const wpSalt = (n) => (btoa(c.records.slice(5) + c.admin.slice(3) + c.db + n).replace(/=+$/, '') + 'aZ9+/kQx3').slice(0, 64);
  const wpConfig = () => `<?php\n/** WordPress base configuration (records corporate site) */\ndefine( 'DB_NAME', 'records_wp' );\ndefine( 'DB_USER', 'records_app' );\ndefine( 'DB_PASSWORD', '${c.db}' );\ndefine( 'DB_HOST', '${DB_HOST}' );\ndefine( 'DB_CHARSET', 'utf8mb4' );\ndefine( 'DB_COLLATE', '' );\n\ndefine( 'AUTH_KEY',         '${wpSalt(1)}' );\ndefine( 'SECURE_AUTH_KEY',  '${wpSalt(2)}' );\ndefine( 'LOGGED_IN_KEY',    '${wpSalt(3)}' );\ndefine( 'NONCE_KEY',        '${wpSalt(4)}' );\ndefine( 'AUTH_SALT',        '${wpSalt(5)}' );\ndefine( 'SECURE_AUTH_SALT', '${wpSalt(6)}' );\ndefine( 'LOGGED_IN_SALT',   '${wpSalt(7)}' );\ndefine( 'NONCE_SALT',       '${wpSalt(8)}' );\n\n// S3 media offload + internal records API\ndefine( 'AWS_ACCESS_KEY_ID',     '${c.akia}' );\ndefine( 'AWS_SECRET_ACCESS_KEY', '${c.asecret}' );\ndefine( 'AWS_S3_BUCKET',         'records-prod-media-271943' );\ndefine( 'RECORDS_API_URL', '${INTERNAL_URL}' );\ndefine( 'RECORDS_API_KEY', '${c.records}' );\n\n$table_prefix = 'wp_';\ndefine( 'WP_DEBUG', false );\nif ( ! defined( 'ABSPATH' ) ) define( 'ABSPATH', __DIR__ . '/' );\nrequire_once ABSPATH . 'wp-settings.php';\n`;
  const m = {
    '/wp-config.php.bak': wpConfig,
    '/wp-config.php~': wpConfig,
    '/wp-config.php.save': wpConfig,
    '/wp-config.php.old': wpConfig,
    '/wp-config.php.orig': wpConfig,
    '/wp-config.php.txt': wpConfig,
    '/wp-config.php.swp': wpConfig,
    '/wp-config.php.dist': wpConfig,
    '/wp-config.php-backup': wpConfig,
    '/wp-config.bak': wpConfig,
    '/wp-config.old': wpConfig,
    '/.wp-config.php.swp': wpConfig,
    // .aws/config (dotted) complements the /.aws/credentials apex bait + /aws/config
    '/.aws/config': () => `[default]\nregion = us-east-2\noutput = json\n[profile records-prod]\nregion = us-east-2\nrole_arn = arn:aws:iam::271943558210:role/records-deploy\nsource_profile = default\n`,
    '/credentials.json': () => JSON.stringify({ records_api: { url: INTERNAL_URL, key: c.records }, aws: { access_key_id: c.akia, secret_access_key: c.asecret, region: 'us-east-2' } }, null, 2),
    '/secrets.json': () => JSON.stringify({ RECORDS_API_KEY: c.records, ADMIN_API_KEY: c.admin, AWS_ACCESS_KEY_ID: c.akia, AWS_SECRET_ACCESS_KEY: c.asecret, MODEL_GATEWAY_KEY: c.bedrock }, null, 2),
    '/.npmrc': () => `//registry.npmjs.org/:_authToken=npm_${c.records.slice(11, 47)}\n@records:registry=https://npm.records.internal/\n//npm.records.internal/:_authToken=${c.records}\n`,
    '/.pgpass': () => `${DB_HOST}:5432:records_prod:records_app:${c.db}\n`,
    '/.my.cnf': () => `[client]\nhost=${DB_HOST}\nuser=records_app\npassword=${c.db}\ndatabase=records_prod\n`,
    '/.s3cfg': () => `[default]\naccess_key = ${c.akia}\nsecret_key = ${c.asecret}\nbucket_location = us-east-2\n`,
    '/.docker/config.json': () => JSON.stringify({ auths: { 'registry.records.internal': { auth: btoa('deploy:' + c.records) }, 'index.docker.io': { auth: btoa('records:' + c.db) } } }, null, 2),
    '/.gem/credentials': () => `---\n:records_api: ${c.records}\n:rubygems_api_key: rubygems_${c.records.slice(11, 43)}\n`,
    '/sendgrid.env': () => `SENDGRID_API_KEY=SG.${c.records.slice(11, 33)}.${c.records.slice(20, 63)}\nMAIL_FROM=noreply@records.internal\n`,
    '/user_secrets.yml': () => `production:\n  records_api_key: ${c.records}\n  secret_key_base: ${c.records.slice(11)}${c.admin.slice(11)}\n  aws_access_key_id: ${c.akia}\n`,
    '/config/master.key': () => c.records.slice(11).replace(/[^a-f0-9]/gi, '0').toLowerCase().padEnd(32, '0').slice(0, 32) + '\n',
    '/appsettings.json': () => JSON.stringify({ ConnectionStrings: { Default: `Server=${DB_HOST};Database=records_prod;User Id=records_app;Password=${c.db};` }, Records: { ApiUrl: INTERNAL_URL, ApiKey: c.records }, AWS: { AccessKey: c.akia, SecretKey: c.asecret } }, null, 2),
    '/appsettings.Production.json': null, // alias filled below
    '/settings.py': () => `# Django settings (prod)\nSECRET_KEY = '${c.records}'\nDATABASES = {'default': {'ENGINE':'django.db.backends.mysql','HOST':'${DB_HOST}','USER':'records_app','PASSWORD':'${c.db}','NAME':'records_prod'}}\nAWS_ACCESS_KEY_ID = '${c.akia}'\nAWS_SECRET_ACCESS_KEY = '${c.asecret}'\nRECORDS_API_URL = '${INTERNAL_URL}'\n`,
    '/parameters.yml': () => `parameters:\n    database_host: ${DB_HOST}\n    database_user: records_app\n    database_password: ${c.db}\n    records_api_key: ${c.records}\n    aws_access_key_id: ${c.akia}\n`,
    '/config/database.yml': () => `production:\n  adapter: mysql2\n  host: ${DB_HOST}\n  username: records_app\n  password: ${c.db}\n  database: records_prod\n`,
    '/sites/default/settings.php': () => `<?php\n$databases['default']['default'] = array('database'=>'records_prod','username'=>'records_app','password'=>'${c.db}','host'=>'${DB_HOST}','driver'=>'mysql');\n$settings['hash_salt'] = '${c.records}';\n`,
    '/app/etc/local.xml': () => `<?xml version="1.0"?>\n<config><global><resources><default_setup><connection>\n<host>${DB_HOST}</host><username>records_app</username><password>${c.db}</password><dbname>records_prod</dbname>\n</connection></default_setup></resources></global></config>\n`,
    '/.bash_history': () => `ls -la\ncat .env\nexport RECORDS_API_KEY=${c.records}\ncurl -H "Authorization: Bearer ${c.records}" ${INTERNAL_URL}/records\naws configure set aws_access_key_id ${c.akia}\nmysql -h ${DB_HOST} -u records_app -p'${c.db}' records_prod\nhistory -c\n`,
    '/storage/logs/laravel.log': () => `[2026-11-22 23:41:07] production.ERROR: Records API auth failed {"url":"${INTERNAL_URL}/records","key":"${c.records}","aws_key":"${c.akia}"} \n[2026-11-22 23:42:10] production.INFO: deploy ok\n`,
    '/.env.bak': () => `RECORDS_API_KEY=${c.records}\nAWS_ACCESS_KEY_ID=${c.akia}\nAWS_SECRET_ACCESS_KEY=${c.asecret}\nDB_PASSWORD=${c.db}\n`,
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
    '/backup.sql': () => `-- records_prod backup\nINSERT INTO app_secrets VALUES (1,'records_api_key','${c.records}'),(2,'aws_access_key_id','${c.akia}');\n`,
    '/database_backup.sql': () => `-- records_prod backup\nINSERT INTO app_secrets VALUES (1,'records_api_key','${c.records}'),(2,'aws_access_key_id','${c.akia}');\n`,
    // CI / deploy pipeline configs (carry deploy + registry secrets)
    '/.github/workflows/main.yml': () => `name: deploy\non: { push: { branches: [main] } }\nenv:\n  AWS_ACCESS_KEY_ID: ${c.akia}\n  AWS_SECRET_ACCESS_KEY: ${c.asecret}\n  RECORDS_API_KEY: ${c.records}\n  RECORDS_API_URL: ${INTERNAL_URL}\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: aws s3 sync ./dist s3://records-prod-data-271943\n`,
    '/.gitlab-ci.yml': () => `variables:\n  AWS_ACCESS_KEY_ID: "${c.akia}"\n  AWS_SECRET_ACCESS_KEY: "${c.asecret}"\n  RECORDS_API_KEY: "${c.records}"\ndeploy:\n  stage: deploy\n  script:\n    - curl -H "Authorization: Bearer $RECORDS_API_KEY" ${INTERNAL_URL}/deploy/status\n`,
    '/Jenkinsfile': () => `pipeline {\n  agent any\n  environment {\n    AWS_ACCESS_KEY_ID = '${c.akia}'\n    RECORDS_API_KEY = '${c.records}'\n    DB_PASSWORD = '${c.db}'\n  }\n  stages { stage('deploy') { steps { sh 'aws s3 sync dist/ s3://records-prod-data-271943' } } }\n}\n`,
    '/.drone.yml': () => `kind: pipeline\nname: default\nsteps:\n- name: deploy\n  image: amazon/aws-cli\n  environment:\n    AWS_ACCESS_KEY_ID: ${c.akia}\n    AWS_SECRET_ACCESS_KEY: ${c.asecret}\n    RECORDS_API_KEY: ${c.records}\n`,
    '/samconfig.toml': () => `version = 0.1\n[default.deploy.parameters]\nstack_name = "records-gateway"\ns3_bucket = "records-prod-data-271943"\nregion = "us-east-2"\nparameter_overrides = "RecordsApiKey=${c.records} AwsAccessKeyId=${c.akia}"\n`,
    // widened cred/config spellings scanners probe that we used to 403
    '/env': () => `RECORDS_API_URL=${INTERNAL_URL}\nRECORDS_API_KEY=${c.records}\nAWS_ACCESS_KEY_ID=${c.akia}\nAWS_SECRET_ACCESS_KEY=${c.asecret}\nDB_HOST=${DB_HOST}\nDB_PASSWORD=${c.db}\n`,
    '/env.js': () => `module.exports = { RECORDS_API_URL: '${INTERNAL_URL}', RECORDS_API_KEY: '${c.records}', AWS_ACCESS_KEY_ID: '${c.akia}', AWS_SECRET_ACCESS_KEY: '${c.asecret}' };\n`,
    '/aws/credentials': () => `[default]\naws_access_key_id = ${c.akia}\naws_secret_access_key = ${c.asecret}\nregion = us-east-2\n`,
    '/config.json': () => JSON.stringify({ recordsApi: { url: INTERNAL_URL, key: c.records }, aws: { accessKeyId: c.akia, secretAccessKey: c.asecret, region: 'us-east-2' }, db: { host: DB_HOST, user: 'records_app', password: c.db } }, null, 2),
    '/config.js': () => `export default { recordsApi: { url: '${INTERNAL_URL}', key: '${c.records}' }, aws: { accessKeyId: '${c.akia}', secretAccessKey: '${c.asecret}' } };\n`,
    '/config.php': () => `<?php\nreturn ['records_api_url'=>'${INTERNAL_URL}','records_api_key'=>'${c.records}','aws_access_key_id'=>'${c.akia}','aws_secret_access_key'=>'${c.asecret}','db_password'=>'${c.db}'];\n`,
    '/settings.json': () => JSON.stringify({ 'records.apiUrl': INTERNAL_URL, 'records.apiKey': c.records, 'aws.accessKeyId': c.akia, 'aws.secretAccessKey': c.asecret }, null, 2),
    '/local.settings.json': () => JSON.stringify({ IsEncrypted: false, Values: { AzureWebJobsStorage: 'DefaultEndpointsProtocol=https;AccountName=recordsprod;AccountKey=' + btoa(c.records).slice(0, 44) + '==;EndpointSuffix=core.windows.net', FUNCTIONS_WORKER_RUNTIME: 'node', RECORDS_API_KEY: c.records, AWS_ACCESS_KEY_ID: c.akia, AWS_SECRET_ACCESS_KEY: c.asecret } }, null, 2),
    '/credentials.yml': () => `records_api:\n  url: ${INTERNAL_URL}\n  key: ${c.records}\naws:\n  access_key_id: ${c.akia}\n  secret_access_key: ${c.asecret}\n  region: us-east-2\n`,
    // Mercurial dump (completes the git/svn/bzr VCS set)
    '/.hg/requires': () => `dotencode\nfncache\ngeneraldelta\nrevlogv1\nstore\n`,
    '/.hg/store/requires': () => `revlogv1\n`,
    '/.hg/hgrc': () => `[paths]\ndefault = https://hg.records.internal/records-web\n[auth]\nrecords.prefix = hg.records.internal\nrecords.username = records_app\nrecords.password = ${c.db}\n`,
    // cloud / dev-tool credential files. creds for internal-api / mcp.honeyd.me
    // resolve to us, so USING them is captured; third-party tokens are realistic
    // fakes caught on grab. key-shaped prefixes are split so no key literal sits
    // in source. all data synthetic.
    '/serverless.yaml': () => `service: records-api\nprovider:\n  name: aws\n  region: us-east-2\n  environment:\n    RECORDS_API_KEY: ${c.records}\n    AWS_ACCESS_KEY_ID: ${c.akia}\n    AWS_SECRET_ACCESS_KEY: ${c.asecret}\nfunctions:\n  api:\n    handler: handler.main\n`,
    '/terraform.tfvars': () => `aws_access_key_id = "${c.akia}"\naws_secret_access_key = "${c.asecret}"\naws_region = "us-east-2"\ndb_password = "${c.db}"\nrecords_api_key = "${c.records}"\n`,
    '/.git-credentials': () => `https://deploy:${c.records}@internal-api.honeyd.me\nhttps://records-bot:${'ghp' + '_' + c.records.slice(11, 47)}@github.com\n`,
    '/.netrc': () => `machine internal-api.honeyd.me\n  login deploy\n  password ${c.records}\nmachine ${DB_HOST}\n  login records_app\n  password ${c.db}\n`,
    '/.pypirc': () => `[distutils]\nindex-servers =\n    records\n\n[records]\nrepository = ${INTERNAL_URL}/pypi\nusername = __token__\npassword = ${c.records}\n`,
    '/.config/gh/hosts.yml': () => `github.com:\n    oauth_token: ${'ghp' + '_' + c.records.slice(11, 47)}\n    user: records-bot\n    git_protocol: https\n`,
    '/.azure/azureProfile.json': () => JSON.stringify({ subscriptions: [{ id: '7f9c0e2a-1b3d-4e5f-6071-8293a4b5c6d7', name: 'records-prod', state: 'Enabled', tenantId: '3a4b5c6d-7e8f-9012-3456-789abcdef012', user: { name: 'deploy@records.internal', type: 'servicePrincipal' } }] }, null, 2),
    '/.claude/settings.json': () => JSON.stringify({ mcpServers: { 'records-gateway': { url: 'https://mcp.honeyd.me/sse', headers: { Authorization: 'Bearer ' + c.mcp } } }, env: { ANTHROPIC_BASE_URL: INTERNAL_URL, ANTHROPIC_API_KEY: 'sk-' + 'ant-api03-' + c.records.slice(11) } }, null, 2),
    '/grafana/provisioning/datasources/default.yml': () => `apiVersion: 1\ndatasources:\n  - name: records-prod-mysql\n    type: mysql\n    url: ${DB_HOST}:3306\n    database: records_prod\n    user: records_app\n    secureJsonData:\n      password: ${c.db}\n  - name: records-api\n    type: prometheus\n    url: ${INTERNAL_URL}\n    secureJsonData:\n      httpHeaderValue1: Bearer ${c.records}\n`,
    '/config/auth.json': () => JSON.stringify({ 'http-basic': { 'internal-api.honeyd.me': { username: 'deploy', password: c.records } }, 'github-oauth': { 'github.com': 'ghp' + '_' + c.records.slice(11, 47) } }, null, 2),
    '/config.yml': () => `records_api:\n  url: ${INTERNAL_URL}\n  key: ${c.records}\naws:\n  access_key_id: ${c.akia}\n  secret_access_key: ${c.asecret}\ndatabase:\n  host: ${DB_HOST}\n  password: ${c.db}\n`,
    '/config/custom-environment-variables.json': () => JSON.stringify({ recordsApiKey: 'RECORDS_API_KEY', aws: { accessKeyId: 'AWS_ACCESS_KEY_ID', secretAccessKey: 'AWS_SECRET_ACCESS_KEY' }, database: { password: 'DB_PASSWORD' } }, null, 2),
    '/env-config.js': () => `window.__ENV__ = { RECORDS_API_URL: '${INTERNAL_URL}', RECORDS_API_KEY: '${c.records}', AWS_REGION: 'us-east-2' };\n`,
    '/aws/config': () => `[default]\nregion = us-east-2\noutput = json\n[profile records-prod]\nregion = us-east-2\nrole_arn = arn:aws:iam::271943558210:role/records-deploy\nsource_profile = default\n`,
    '/configuration.php': () => `<?php\nclass JConfig {\n\tpublic $host = '${DB_HOST}';\n\tpublic $user = 'records_app';\n\tpublic $password = '${c.db}';\n\tpublic $db = 'records_prod';\n\tpublic $secret = '${c.records}';\n}\n`,
    '/settings.php': () => `<?php\n$databases['default']['default'] = array('database'=>'records_prod','username'=>'records_app','password'=>'${c.db}','host'=>'${DB_HOST}','driver'=>'mysql');\n$settings['hash_salt'] = '${c.records}';\n`,
    '/app/config/parameters.yml': () => `parameters:\n    database_host: ${DB_HOST}\n    database_user: records_app\n    database_password: ${c.db}\n    records_api_key: ${c.records}\n    aws_access_key_id: ${c.akia}\n`,
    '/site.sql': () => `-- records_prod backup\nINSERT INTO app_secrets VALUES (1,'records_api_key','${c.records}'),(2,'aws_access_key_id','${c.akia}'),(3,'db_password','${c.db}');\n`,
    '/appsettings.Development.json': null, // alias filled below
  };
  m['/appsettings.Production.json'] = m['/appsettings.json'];
  m['/appsettings.Development.json'] = m['/appsettings.json'];
  m['/config.php.bak'] = m['/config.php'];
  m['/config.php.old'] = m['/config.php'];
  m['/config.php~'] = m['/config.php'];
  m['/config.php.save'] = m['/config.php'];
  m['/config.php.txt'] = m['/config.php'];
  return m;
}

// ---- EC2 instance metadata service (IMDS) ----
// The SSRF/cloud-cred crowd (same actors abusing the AWS key for Bedrock) pivot
// through IMDS to lift role credentials. Serve believable metadata whose role
// creds are the AWS canary, so lifting them trips the tripwire the moment used.
async function imds(path, method, env) {
  if (path === '/latest/api/token') return { body: 'AQAEAP' + b64line(rng(4711), 50).replace(/[+/=]/g, 'x'), ct: TEXT_H };
  if (method !== 'GET') return null;
  const ROLE = 'records-ec2-role';
  if (path === '/latest/meta-data/iam/security-credentials/' + ROLE) {
    const c = await creds(env);
    return { body: JSON.stringify({ Code: 'Success', LastUpdated: '2026-11-23T20:14:03Z', Type: 'AWS-HMAC', AccessKeyId: c.akia, SecretAccessKey: c.asecret, Token: 'IQoJb3JpZ2luX2Vj' + b64line(rng(9931), 180), Expiration: '2026-11-24T02:14:03Z' }, null, 2), ct: JSON_H };
  }
  if (path === '/latest/dynamic/instance-identity/document') {
    return { body: JSON.stringify({ accountId: '271943558210', region: 'us-east-2', availabilityZone: 'us-east-2b', instanceId: 'i-0a7f2c9d1e3b5a8c0', instanceType: 'm6i.xlarge', imageId: 'ami-0c7f2a3b4d5e6f708', architecture: 'x86_64', pendingTime: '2026-10-02T11:20:41Z', version: '2017-09-30' }, null, 2), ct: JSON_H };
  }
  const map = {
    '/latest/meta-data': 'ami-id\nhostname\niam/\ninstance-id\ninstance-type\nlocal-ipv4\nmac\nplacement/\npublic-ipv4\nreservation-id\nsecurity-groups\n',
    '/latest/meta-data/iam': 'info\nsecurity-credentials/\n',
    '/latest/meta-data/iam/security-credentials': ROLE,
    '/latest/meta-data/iam/info': JSON.stringify({ Code: 'Success', LastUpdated: '2026-11-22T23:41:07Z', InstanceProfileArn: 'arn:aws:iam::271943558210:instance-profile/records-ec2-profile', InstanceProfileId: 'AIPAJ5R2VQ7T3K9W2YH1' }, null, 2),
    '/latest/meta-data/instance-id': 'i-0a7f2c9d1e3b5a8c0',
    '/latest/meta-data/instance-type': 'm6i.xlarge',
    '/latest/meta-data/local-ipv4': '10.0.3.47',
    '/latest/meta-data/placement/region': 'us-east-2',
    '/latest/meta-data/security-groups': 'records-app-sg\nrecords-db-sg\n',
  };
  if (map[path] != null) return { body: map[path], ct: TEXT_H };
  if (path.startsWith('/latest/meta-data')) return { body: '', ct: TEXT_H };
  return null;
}

// ---- Terraform state (plaintext provider creds + infra inventory) ----
async function tfstate(env) {
  const c = await creds(env);
  const PROV = 'provider["registry.terraform.io/hashicorp/aws"]';
  return JSON.stringify({
    version: 4, terraform_version: '1.9.5', serial: 47, lineage: '3f1c0e2a-1b3d-4e5f-6071-8293a4b5c6d7',
    outputs: {
      records_api_key: { value: c.records, type: 'string', sensitive: true },
      model_gateway_url: { value: INTERNAL_URL, type: 'string' },
      aws_access_key_id: { value: c.akia, type: 'string', sensitive: true },
      db_endpoint: { value: DB_HOST + ':3306', type: 'string' },
    },
    resources: [
      { mode: 'managed', type: 'aws_db_instance', name: 'records', provider: PROV, instances: [{ attributes: { address: DB_HOST, engine: 'mysql', username: 'records_app', password: c.db, db_name: 'records_prod', port: 3306 } }] },
      { mode: 'managed', type: 'aws_s3_bucket', name: 'records_data', provider: PROV, instances: [{ attributes: { bucket: 'records-prod-data-271943', region: 'us-east-2' } }] },
      { mode: 'managed', type: 'aws_iam_access_key', name: 'deploy', provider: PROV, instances: [{ attributes: { id: c.akia, secret: c.asecret, user: 'records-deploy', status: 'Active' } }] },
    ],
  }, null, 2);
}

// ---- OpenAPI / Swagger spec that advertises the fake API incl. the LLM endpoint ----
function openApiSpec() {
  return JSON.stringify({
    openapi: '3.0.3',
    info: { title: 'records-gateway', version: '2.4.1', description: 'Internal records + model gateway. Authenticate with a service key: Authorization: Bearer <RECORDS_API_KEY>.' },
    servers: [{ url: INTERNAL_URL }],
    components: { securitySchemes: { bearerAuth: { type: 'http', scheme: 'bearer' } } },
    security: [{ bearerAuth: [] }],
    paths: {
      '/chat/completions': { post: { summary: 'OpenAI-compatible chat completions via the model gateway', requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { model: { type: 'string' }, messages: { type: 'array', items: { type: 'object' } } } } } } }, responses: { 200: { description: 'completion' } } } },
      '/records': { get: { summary: 'List records' }, post: { summary: 'Create record' } },
      '/records/{id}': { get: { summary: 'Get record', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }] } },
      '/users': { get: { summary: 'List users (admin)' } },
      '/secrets': { get: { summary: 'Service secrets (tiered)' } },
      '/vault': { get: { summary: 'Vault secrets (secrets:admin)' } },
    },
  }, null, 2);
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
  // EC2 IMDS (handles GET subpaths + the IMDSv2 PUT token, so before the GET gate)
  if (path === '/latest/api/token' || path.startsWith('/latest/')) {
    const r = await imds(path, method, env);
    if (r) return { response: R(r.body, r.ct), label: 'imds:' + path };
  }
  if (method !== 'GET') return null;

  if (path === '/terraform.tfstate' || path === '/terraform.tfstate.backup' || path === '/.terraform/terraform.tfstate') return { response: R(await tfstate(env), JSON_H), label: 'tfstate:' + path };
  if (path === '/openapi.json' || path === '/swagger.json' || path === '/swagger/v1/swagger.json' || path === '/v3/api-docs' || path === '/api-docs' || path === '/api/openapi.json') return { response: R(openApiSpec(), JSON_H), label: 'openapi:' + path };

  if (ACTUATOR[path]) return { response: R(await ACTUATOR[path](env), path === '/actuator/heapdump' ? TEXT_H : JSON_H), label: 'actuator:' + path };
  if (PHPINFO_RE.test(path)) return { response: R(await phpinfo(env), HTML_H), label: 'phpinfo:' + path };
  if (path === '/v2/_catalog' || path === '/v2' || path === '/v2/') return { response: R(JSON.stringify({ repositories: ['records-api', 'records-worker', 'records-migrate', 'internal/backup'] }), JSON_H), label: 'registry:catalog' };
  let rm;
  if ((rm = path.match(/^\/v2\/([a-z0-9][a-z0-9._/-]*)\/tags\/list$/))) return { response: R(JSON.stringify({ name: rm[1], tags: ['latest', '2.4.1', '2.4.0', '2.3.7', 'stable'] }), JSON_H), label: 'registry:tags:' + rm[1] };
  if ((rm = path.match(/^\/v2\/([a-z0-9][a-z0-9._/-]*)\/manifests\/[^/]+$/))) return { response: R(JSON.stringify({ schemaVersion: 2, mediaType: 'application/vnd.docker.distribution.manifest.v2+json', config: { mediaType: 'application/vnd.docker.container.image.v1+json', size: 7023, digest: 'sha256:3f1c0e2a1b3d4e5f60718293a4b5c6d7e8f901122334455667788990011aabbcc' }, layers: [{ mediaType: 'application/vnd.docker.image.rootfs.diff.tar.gzip', size: 32654187, digest: 'sha256:a3f91c7b2d4e6f80912345678901234567890abcdef1234567890abcdef123456' }] }), { ...JSON_H, 'Content-Type': 'application/vnd.docker.distribution.manifest.v2+json' }), label: 'registry:manifest:' + rm[1] };
  if ((rm = path.match(/^\/v2\/[a-z0-9][a-z0-9._/-]*\/blobs\/sha256:[a-f0-9]+$/))) { const c = await creds(env); return { response: R(JSON.stringify({ architecture: 'amd64', os: 'linux', config: { Env: [`RECORDS_API_URL=${INTERNAL_URL}`, `RECORDS_API_KEY=${c.records}`, `AWS_ACCESS_KEY_ID=${c.akia}`, `AWS_SECRET_ACCESS_KEY=${c.asecret}`, `DB_HOST=${DB_HOST}`, `DB_PASSWORD=${c.db}`], Entrypoint: ['/app/records-api'], WorkingDir: '/app' } }), JSON_H), label: 'registry:blob' }; }
  if (path === '/.svn/wc.db' || path === '/.svn/entries') { const c = await creds(env); return { response: R('SQLite format 3\x00-- records_prod working copy\nrecords.api.key=' + c.records + '\n', TEXT_H), label: 'svn' }; }
  if (path === '/.bzr/branch/branch.conf') return { response: R('parent_location = https://git.records.internal/records-web\n', TEXT_H), label: 'bzr' };

  const files = await credFiles(env);
  if (files[path]) return { response: R(files[path](), ctFor(path)), label: 'credfile:' + path };
  return null;
}
