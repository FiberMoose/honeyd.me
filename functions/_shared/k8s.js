// Fake Kubernetes API on k8s.honeyd.me. The leaked kubeconfig points kubectl
// here with a bearer token; a scanner/agent that acts on it reaches a cluster
// that behaves like the real thing: the discovery endpoints (/version, /healthz,
// /api, /apis) answer WITHOUT auth, exactly like a real apiserver, and the
// protected resources 401 unless the planted token is presented. Present the
// planted token and you get namespaces, pods, and secrets whose data is the
// canary creds (base64), so pulling a secret and using it trips the tripwire.
// All data is synthetic; real secret values are injected from KV at request time.
import { secret } from './secret.js';

// the exact token from the leaked kubeconfig (bait.js KUBECONFIG). Public fake.
const K8S_TOKEN = 'eyJhbGciOiJSUzI1NiIsImtpZCI6Imhkc3ZjIn0.hd_k8s_Qn7Vb2Mx9Lp4Tc8Wk.Rg3Yd6Sz1Fv0';
const INTERNAL_KEY = 'hd_live_sk_8Fq2Lp9Rv4Tc7Wb3Yn6Dx1Sg5Hm0Kj';
const INTERNAL_URL = 'https://internal-api.honeyd.me/v1';
const DB_HOST = 'honeyd-prod.cluster-ro-c7k2x9q8.us-east-2.rds.amazonaws.com';
const DB_PASS = 'Hv7kQ2pX9mB4tLwZ';
const NS = ['default', 'kube-system', 'honeyd-prod', 'monitoring'];

const JSON_H = { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' };
const TEXT_H = { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' };
const b64 = (s) => btoa(String(s));
const J = (obj, status = 200) => new Response(JSON.stringify(obj), { status, headers: JSON_H });
const T = (s, status = 200) => new Response(s, { status, headers: TEXT_H });
const statusObj = (code, reason, message, extra) => ({ kind: 'Status', apiVersion: 'v1', metadata: {}, status: 'Failure', message, reason, code, ...extra });
const r401 = () => J(statusObj(401, 'Unauthorized', 'Unauthorized'), 401);
const r403 = (msg) => J(statusObj(403, 'Forbidden', msg || 'forbidden'), 403);
const r404 = (msg) => J(statusObj(404, 'NotFound', msg || 'the server could not find the requested resource'), 404);

const VERSION = { major: '1', minor: '29', gitVersion: 'v1.29.4', gitCommit: '55e706fd3d6b8c5e9b6d9e8a1f2c3d4e5f607182', gitTreeState: 'clean', buildDate: '2026-09-18T11:20:41Z', goVersion: 'go1.22.1', compiler: 'gc', platform: 'linux/amd64' };
const API_VERSIONS = { kind: 'APIVersions', versions: ['v1'], serverAddressByClientCIDRs: [{ clientCIDR: '0.0.0.0/0', serverAddress: '10.0.0.1:443' }] };
const API_GROUPS = { kind: 'APIGroupList', apiVersion: 'v1', groups: ['apps', 'batch', 'networking.k8s.io', 'rbac.authorization.k8s.io', 'apiextensions.k8s.io'].map((g) => ({ name: g, versions: [{ groupVersion: g + '/v1', version: 'v1' }], preferredVersion: { groupVersion: g + '/v1', version: 'v1' } })) };

function podList(ns) {
  const mk = (app, i) => ({ metadata: { name: `${app}-${(7 + i).toString(16)}f${(i * 97 % 900 + 100)}-${['x9k2', 'p4lq', 'v7bm', 't3wd'][i % 4]}`, namespace: ns, labels: { app } }, status: { phase: 'Running', podIP: `10.1.${(i % 6) + 2}.${(i * 37) % 250 + 3}`, startTime: '2026-11-22T23:41:07Z' }, spec: { serviceAccountName: app, containers: [{ name: app, image: `registry.records.internal/${app}:2.4.1` }] } });
  const apps = ns === 'kube-system' ? ['coredns', 'kube-proxy', 'metrics-server'] : ns === 'monitoring' ? ['prometheus', 'grafana'] : ['records-api', 'records-worker', 'records-migrate'];
  return { kind: 'PodList', apiVersion: 'v1', items: apps.flatMap((a, i) => [mk(a, i), mk(a, i + 4)]) };
}

async function secretData(env, name) {
  const akia = (await secret(env, 'aws_akia')) || '';
  const asec = (await secret(env, 'aws_secret')) || '';
  if (name === 'aws-credentials') return { AWS_ACCESS_KEY_ID: b64(akia), AWS_SECRET_ACCESS_KEY: b64(asec), AWS_DEFAULT_REGION: b64('us-east-2') };
  if (name === 'records-api-credentials') return { 'api-url': b64(INTERNAL_URL), 'api-key': b64(INTERNAL_KEY) };
  if (name === 'db-credentials') return { host: b64(DB_HOST), username: b64('records_app'), password: b64(DB_PASS), database: b64('records_prod') };
  if (name === 'registry-pull') return { '.dockerconfigjson': b64(JSON.stringify({ auths: { 'registry.records.internal': { auth: b64('deploy:' + INTERNAL_KEY) } } })) };
  return null;
}
const SECRET_NAMES = ['records-api-credentials', 'aws-credentials', 'db-credentials', 'registry-pull', 'default-token-k9x2f'];
function secretList(ns) {
  return { kind: 'SecretList', apiVersion: 'v1', items: SECRET_NAMES.map((n) => ({ metadata: { name: n, namespace: ns, creationTimestamp: '2026-11-22T23:41:07Z' }, type: n === 'registry-pull' ? 'kubernetes.io/dockerconfigjson' : n.startsWith('default-token') ? 'kubernetes.io/service-account-token' : 'Opaque' })) };
}

// Returns { response, logPath, alert }.
export async function handleK8s(request, env) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, '') || '/';
  const tok = (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '').trim();
  const authed = tok === K8S_TOKEN;
  const out = (response, label, alert) => ({ response, logPath: label, alert: !!alert });

  // --- unauthenticated discovery: a real apiserver answers these with no creds
  if (path === '/version') return out(J(VERSION), '/version', false);
  if (path === '/healthz' || path === '/livez' || path === '/readyz') return out(T('ok'), path, false);
  if (path === '/api' || path === '/api/v1') return out(J(path === '/api' ? API_VERSIONS : { kind: 'APIResourceList', groupVersion: 'v1', resources: ['namespaces', 'pods', 'secrets', 'configmaps', 'services', 'nodes', 'serviceaccounts'].map((n) => ({ name: n, namespaced: n !== 'namespaces' && n !== 'nodes', kind: n.replace(/s$/, '').replace(/^./, (c) => c.toUpperCase()) })) }), path, false);
  if (path === '/apis') return out(J(API_GROUPS), '/apis', false);
  if (path === '/openapi/v2' || path === '/openapi/v3') return out(J({ swagger: '2.0', info: { title: 'Kubernetes', version: 'v1.29.4' }, paths: {} }), path, false);
  if (path === '/.well-known/openid-configuration') return out(J({ issuer: 'https://k8s.honeyd.me', jwks_uri: 'https://k8s.honeyd.me/openid/v1/jwks', response_types_supported: ['id_token'], subject_types_supported: ['public'], id_token_signing_alg_values_supported: ['RS256'] }), path, false);

  // --- protected resources: 401 unless the planted kubeconfig token is presented
  if (/^\/(api|apis)\//.test(path)) {
    if (!authed) return out(r401(), path + (tok ? ' [badtoken]' : ' [noauth]'), false);

    // authed with OUR planted token => the catch. serve fake cluster data; secrets carry canaries.
    if (path === '/api/v1/namespaces') return out(J({ kind: 'NamespaceList', apiVersion: 'v1', items: NS.map((n) => ({ metadata: { name: n }, status: { phase: 'Active' } })) }), path + ' [authed]', true);
    let m;
    if ((m = path.match(/^\/api\/v1\/namespaces\/([^/]+)\/pods$/))) return out(J(podList(m[1])), path + ' [authed]', true);
    if ((m = path.match(/^\/api\/v1\/namespaces\/([^/]+)\/secrets$/))) return out(J(secretList(m[1])), path + ' [authed]', true);
    if ((m = path.match(/^\/api\/v1\/namespaces\/([^/]+)\/secrets\/([^/]+)$/))) {
      const data = await secretData(env, m[2]);
      if (!data) return out(r404('secrets "' + m[2] + '" not found'), path + ' [authed:miss]', true);
      const type = m[2] === 'registry-pull' ? 'kubernetes.io/dockerconfigjson' : 'Opaque';
      return out(J({ kind: 'Secret', apiVersion: 'v1', metadata: { name: m[2], namespace: m[1] }, type, data }), path + ' [authed:SECRET]', true);
    }
    if ((m = path.match(/^\/api\/v1\/namespaces\/([^/]+)\/configmaps$/))) return out(J({ kind: 'ConfigMapList', apiVersion: 'v1', items: [{ metadata: { name: 'records-config', namespace: m[1] }, data: { RECORDS_API_URL: INTERNAL_URL, DB_HOST, AWS_REGION: 'us-east-2' } }] }), path + ' [authed]', true);
    if (path === '/api/v1/nodes') return out(J({ kind: 'NodeList', apiVersion: 'v1', items: ['ip-10-0-3-21', 'ip-10-0-4-12', 'ip-10-0-5-9'].map((n) => ({ metadata: { name: n + '.us-east-2.compute.internal', labels: { 'node.kubernetes.io/instance-type': 'm6i.xlarge' } }, status: { nodeInfo: { kubeletVersion: 'v1.29.4', osImage: 'Ubuntu 24.04.1 LTS' } } })) }), path + ' [authed]', true);
    if (path === '/api/v1/secrets') return out(J(secretList('default')), path + ' [authed]', true);
    if (path === '/api/v1/pods') return out(J(podList('honeyd-prod')), path + ' [authed]', true);
    return out(J({ kind: 'List', apiVersion: 'v1', items: [] }), path + ' [authed]', true);
  }
  return out(r404(), path, false);
}
