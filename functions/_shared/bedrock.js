// Fake AWS Bedrock surface. The LLMjacking crowd validates stolen AWS creds for
// Bedrock access (Datadog "Beyond valid credentials" + Sysdig LLMjacking). Our
// real AWS key is a Thinkst canary, so that validation hits REAL AWS and we only
// see the trigger. This emulates the Bedrock control-plane + runtime on OUR infra,
// lured via a planted AWS_BEARER_TOKEN_BEDROCK + AWS_ENDPOINT_URL_BEDROCK in .env,
// so the full sequence + prompts land here. All synthetic; nothing touches AWS.
import { JSON_HEADERS } from './bait.js';

const REGIONS = ['us-east-1', 'us-west-2', 'ap-southeast-1', 'ap-northeast-1', 'eu-central-1', 'eu-west-3', 'us-gov-west-1'];

function catalog() {
  const mk = (id, name, provider, stream, types) => ({
    modelArn: `arn:aws:bedrock:us-east-1::foundation-model/${id}`,
    modelId: id, modelName: name, providerName: provider,
    inputModalities: ['TEXT'], outputModalities: ['TEXT'],
    responseStreamingSupported: stream, customizationsSupported: [],
    inferenceTypesSupported: types, modelLifecycle: { status: 'ACTIVE' },
  });
  return [
    mk('anthropic.claude-v2', 'Claude', 'Anthropic', true, ['ON_DEMAND']),
    mk('anthropic.claude-v2:1', 'Claude', 'Anthropic', true, ['ON_DEMAND']),
    mk('anthropic.claude-3-5-sonnet-20241022-v2:0', 'Claude 3.5 Sonnet v2', 'Anthropic', true, ['INFERENCE_PROFILE']),
    mk('anthropic.claude-opus-5', 'Claude Opus 5', 'Anthropic', true, ['INFERENCE_PROFILE']),
    mk('amazon.nova-lite-v1:0', 'Nova Lite', 'Amazon', true, ['ON_DEMAND']),
    mk('amazon.titan-text-lite-v1', 'Titan Text G1 - Lite', 'Amazon', true, ['ON_DEMAND']),
    mk('meta.llama3-1-8b-instruct-v1:0', 'Llama 3.1 8B Instruct', 'Meta', true, ['ON_DEMAND']),
    mk('mistral.mixtral-8x7b-instruct-v0:1', 'Mixtral 8x7B Instruct', 'Mistral AI', true, ['ON_DEMAND']),
  ];
}

function err(type, message, status) {
  return new Response(JSON.stringify({ message, __type: type }), {
    status, headers: { ...JSON_HEADERS, 'x-amzn-ErrorType': type, 'Cache-Control': 'no-store' },
  });
}

function reply(messages) {
  let t = '';
  if (messages && messages.length) { const c = messages[messages.length - 1]; t = (typeof c === 'string' ? c : (c && c.content)) || ''; if (Array.isArray(t)) t = t.map((x) => (x && x.text) || '').join(' '); }
  t = String(t).trim();
  const m = t.match(/\b(?:reply|respond|say|output|print|return)\s+(?:exactly|only|with|back)?\s*[:\s]*["'`]?([^"'`\n]{1,40}?)["'`]?\s*$/i);
  if (m && m[1]) return m[1].trim();
  if (/^ping$/i.test(t)) return 'pong';
  return 'Hello! How can I help you today?';
}

async function logBedrock(env, r) {
  if (!env.DB) return;
  try {
    await env.DB.prepare('CREATE TABLE IF NOT EXISTS bedrock_hits (ts TEXT, ip TEXT, token TEXT, action TEXT, model TEXT, path TEXT, body TEXT, result TEXT, tls TEXT, cipher TEXT, ua TEXT, country TEXT, asn TEXT, as_org TEXT)').run();
    await env.DB.prepare('INSERT INTO bedrock_hits (ts,ip,token,action,model,path,body,result,tls,cipher,ua,country,asn,as_org) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)').bind(
      new Date().toISOString(), r.ip || '', (r.token || '').slice(0, 80), r.action || '', r.model || '', (r.path || '').slice(0, 200),
      (r.body || '').slice(0, 8000), r.result || '', r.tls || '', r.cipher || '', (r.ua || '').slice(0, 300), r.country || '', r.asn || '', r.as_org || '',
    ).run();
  } catch {}
}

// Returns {response, row, alert} for a Bedrock-shaped request on any host, else null.
export async function handleBedrock(request, env, m) {
  const url = new URL(request.url);
  const p = url.pathname;
  const method = request.method;
  const isBedrock = p === '/foundation-models' || p.startsWith('/foundation-models/') ||
    p === '/inference-profiles' || p === '/logging/modelinvocations' ||
    /^\/model\/[^/]+\/(converse|converse-stream|invoke|invoke-with-response-stream)$/.test(p);
  if (!isBedrock) return null;

  const token = (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '').slice(0, 80);
  const base = { ip: m && m.ip, token, tls: m && m.tls, cipher: m && m.cipher, ua: m && m.ua, country: m && m.country, asn: m && m.asn, as_org: m && m.as_org, path: p };
  const out = async (resp, action, model, body, result) => {
    await logBedrock(env, { ...base, action, model: model || '', body: body || '', result: result || String(resp.status) });
    return { response: resp, row: { host: 'bedrock', path: `${action}${model ? ':' + model : ''}`, method, status: resp.status, ...base }, alert: true };
  };

  // GET /logging/modelinvocations -> logging DISABLED (attackers avoid logged keys)
  if (method === 'GET' && p === '/logging/modelinvocations') {
    return out(new Response(JSON.stringify({ loggingConfig: null }), { status: 200, headers: JSON_HEADERS }), 'GetModelInvocationLoggingConfiguration');
  }
  // GET /foundation-models  (ListFoundationModels)
  if (method === 'GET' && p === '/foundation-models') {
    let models = catalog();
    const prov = (url.searchParams.get('byProvider') || '').toLowerCase();
    if (prov) models = models.filter((x) => x.providerName.toLowerCase().includes(prov));
    return out(new Response(JSON.stringify({ modelSummaries: models }), { status: 200, headers: JSON_HEADERS }), 'ListFoundationModels');
  }
  // GET /foundation-models/{id}  (GetFoundationModel)
  if (method === 'GET' && p.startsWith('/foundation-models/')) {
    const id = decodeURIComponent(p.slice('/foundation-models/'.length));
    const f = catalog().find((x) => x.modelId === id);
    if (!f) return out(err('ResourceNotFoundException', `Could not find model: ${id}`, 404), 'GetFoundationModel', id);
    return out(new Response(JSON.stringify({ modelDetails: f }), { status: 200, headers: JSON_HEADERS }), 'GetFoundationModel', id);
  }
  // GET /inference-profiles
  if (method === 'GET' && p === '/inference-profiles') {
    const profs = [
      { inferenceProfileName: 'US Anthropic Claude Opus 5', inferenceProfileId: 'us.anthropic.claude-opus-5', inferenceProfileArn: 'arn:aws:bedrock:us-east-1:271943558210:inference-profile/us.anthropic.claude-opus-5', status: 'ACTIVE', type: 'SYSTEM_DEFINED' },
      { inferenceProfileName: 'US Anthropic Claude 3.5 Sonnet v2', inferenceProfileId: 'us.anthropic.claude-3-5-sonnet-20241022-v2:0', inferenceProfileArn: 'arn:aws:bedrock:us-east-1:271943558210:inference-profile/us.anthropic.claude-3-5-sonnet-20241022-v2:0', status: 'ACTIVE', type: 'SYSTEM_DEFINED' },
    ];
    return out(new Response(JSON.stringify({ inferenceProfileSummaries: profs }), { status: 200, headers: JSON_HEADERS }), 'ListInferenceProfiles');
  }

  // POST /model/{id}/converse|invoke
  const rm = p.match(/^\/model\/([^/]+)\/(converse|converse-stream|invoke|invoke-with-response-stream)$/);
  if (rm && method === 'POST') {
    const model = decodeURIComponent(rm[1]);
    const action = rm[2];
    let raw = '';
    try { raw = await request.text(); } catch {}
    let body = {}; try { body = JSON.parse(raw || '{}'); } catch {}

    // Anthropic "use case details" gate: AWS returns 404 until the form is approved.
    // Fire it for a deterministic subset of anthropic models so sequencing looks real.
    if (model.startsWith('anthropic.') && (model.includes('opus') || model.includes('v2:1'))) {
      return out(err('ResourceNotFoundException', `Could not resolve the foundation model from the provided model identifier. You may need to submit a request for access to the model, including use case details, before you can use it.`, 404), 'InvokeModel', model, raw);
    }
    // InvokeModel live-vs-denied tell: max_tokens_to_sample out of range -> ValidationException
    const mts = body.max_tokens_to_sample;
    if (action.startsWith('invoke') && mts != null && (mts < 1 || mts > 1000000)) {
      return out(err('ValidationException', 'Malformed input request: #/max_tokens_to_sample: must have a minimum value of 1 and a maximum value of 1000000, please reformat your input and try again.', 400), 'InvokeModel', model, raw);
    }

    const msgs = body.messages || (body.prompt ? [{ role: 'user', content: body.prompt }] : []);
    const text = reply(msgs);
    const itok = Math.max(1, (raw.length >> 2)); const otok = Math.max(1, (text.length >> 2));
    let resp;
    if (action.startsWith('converse')) {
      resp = new Response(JSON.stringify({
        output: { message: { role: 'assistant', content: [{ text }] } },
        stopReason: 'end_turn', usage: { inputTokens: itok, outputTokens: otok, totalTokens: itok + otok },
        metrics: { latencyMs: 300 + (itok % 400) },
      }), { status: 200, headers: JSON_HEADERS });
    } else {
      // InvokeModel: claude text-completions shape
      resp = new Response(JSON.stringify({ type: 'completion', completion: ' ' + text, stop_reason: 'stop_sequence', stop: '\n\nHuman:' }), { status: 200, headers: JSON_HEADERS });
    }
    return out(resp, action.startsWith('converse') ? 'Converse' : 'InvokeModel', model, raw, 'ok');
  }

  return null;
}
