// Fake AWS Bedrock surface (control-plane + runtime), matched to the real API
// contract so it is hard to tell from a genuine endpoint. The LLMjacking crowd
// (Datadog "Beyond valid credentials" + Sysdig LLMjacking) validates stolen creds
// for Bedrock; our real AWS key is a Thinkst canary, so that validation hits real
// AWS and we only see the trigger. This emulates Bedrock on OUR infra, lured via a
// planted AWS_BEARER_TOKEN_BEDROCK + AWS_ENDPOINT_URL_BEDROCK in .env, so the full
// sequence + prompts land here. All synthetic; nothing touches AWS.
import { JSON_HEADERS } from './bait.js';
import { relayLlm, fallbackCompletion, llmGate } from './api.js';

const reqId = () => (globalThis.crypto && crypto.randomUUID ? crypto.randomUUID() : (Date.now().toString(16) + Math.random().toString(16).slice(2, 10)));
// every real AWS response carries x-amzn-RequestId; add it to all of ours. Real
// Bedrock Content-Type is "application/json" with no charset, so override that.
const H = (extra) => ({ ...JSON_HEADERS, 'Content-Type': 'application/json', 'x-amzn-RequestId': reqId(), 'Cache-Control': 'no-store', ...(extra || {}) });

function catalog() {
  const mk = (id, name, provider, types) => ({
    modelArn: `arn:aws:bedrock:us-east-1::foundation-model/${id}`,
    modelId: id, modelName: name, providerName: provider,
    inputModalities: ['TEXT'], outputModalities: ['TEXT'],
    responseStreamingSupported: true, customizationsSupported: [],
    inferenceTypesSupported: types, modelLifecycle: { status: 'ACTIVE' },
  });
  // modelName <= 20 chars and providerName <= 20 per the real FoundationModelSummary.
  // Cross-region Anthropic models are INFERENCE_PROFILE-only in real Bedrock.
  return [
    mk('anthropic.claude-v2', 'Claude', 'Anthropic', ['ON_DEMAND']),
    mk('anthropic.claude-v2:1', 'Claude', 'Anthropic', ['ON_DEMAND']),
    mk('anthropic.claude-3-5-sonnet-20241022-v2:0', 'Claude 3.5 Sonnet v2', 'Anthropic', ['INFERENCE_PROFILE']),
    mk('anthropic.claude-opus-5', 'Claude Opus 5', 'Anthropic', ['INFERENCE_PROFILE']),
    mk('amazon.nova-lite-v1:0', 'Nova Lite', 'Amazon', ['ON_DEMAND', 'INFERENCE_PROFILE']),
    mk('amazon.titan-text-lite-v1', 'Titan Text G1 - Lite', 'Amazon', ['ON_DEMAND']),
    mk('meta.llama3-1-8b-instruct-v1:0', 'Llama 3.1 8B', 'Meta', ['ON_DEMAND']),
    mk('mistral.mixtral-8x7b-instruct-v0:1', 'Mixtral 8x7B', 'Mistral AI', ['ON_DEMAND']),
  ];
}

// Bedrock (restJson1) errors: body {"message": "..."} + x-amzn-errortype header.
function err(type, message, status) {
  return new Response(JSON.stringify({ message }), { status, headers: H({ 'x-amzn-errortype': type }) });
}

// ---- amazon eventstream (application/vnd.amazon.eventstream) encoder ----
function crc32(buf) { let c = ~0 >>> 0; for (let i = 0; i < buf.length; i++) { c ^= buf[i]; for (let k = 0; k < 8; k++) c = ((c >>> 1) ^ (0xEDB88320 & -(c & 1))) >>> 0; } return (~c) >>> 0; }
function esMessage(eventType, payloadObj) {
  const enc = new TextEncoder();
  const hdr = (name, val) => { const n = enc.encode(name), v = enc.encode(val); const o = [n.length, ...n, 7, (v.length >> 8) & 0xff, v.length & 0xff, ...v]; return o; };
  const headers = Uint8Array.from([...hdr(':event-type', eventType), ...hdr(':content-type', 'application/json'), ...hdr(':message-type', 'event')]);
  const payload = enc.encode(JSON.stringify(payloadObj));
  const total = 16 + headers.length + payload.length;
  const prelude = new Uint8Array(8); const pdv = new DataView(prelude.buffer); pdv.setUint32(0, total); pdv.setUint32(4, headers.length);
  const pc = new Uint8Array(4); new DataView(pc.buffer).setUint32(0, crc32(prelude));
  const body = new Uint8Array(12 + headers.length + payload.length);
  body.set(prelude, 0); body.set(pc, 8); body.set(headers, 12); body.set(payload, 12 + headers.length);
  const mc = new Uint8Array(4); new DataView(mc.buffer).setUint32(0, crc32(body));
  const full = new Uint8Array(body.length + 4); full.set(body, 0); full.set(mc, body.length);
  return full;
}
function eventStream(messages) { let len = 0; for (const m of messages) len += m.length; const out = new Uint8Array(len); let o = 0; for (const m of messages) { out.set(m, o); o += m.length; } return out; }

// extract the user text from a Converse / InvokeModel body into OpenAI messages
function toMessages(body) {
  if (Array.isArray(body.messages)) {
    return body.messages.map((m) => {
      let c = m.content;
      if (Array.isArray(c)) c = c.map((x) => (x && (x.text || x.content)) || '').join(' ');
      return { role: m.role || 'user', content: String(c == null ? '' : c) };
    });
  }
  if (typeof body.prompt === 'string') return [{ role: 'user', content: body.prompt.replace(/\n*Human:\s*|\n*Assistant:\s*/g, ' ').trim() }];
  if (body.inputText) return [{ role: 'user', content: String(body.inputText) }];
  return [];
}
async function complete(env, ip, messages) {
  let text = null;
  if (await llmGate(env, ip)) text = await relayLlm(env, messages);
  if (text == null) text = fallbackCompletion(messages);
  return text;
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

  // GET /logging/modelinvocations -> no logging configured (body {}). Attackers
  // avoid keys with logging on ("privacy"); an empty config = logging off -> they use it.
  if (method === 'GET' && p === '/logging/modelinvocations') {
    return out(new Response('{}', { status: 200, headers: H() }), 'GetModelInvocationLoggingConfiguration');
  }
  // GET /foundation-models (ListFoundationModels)
  if (method === 'GET' && p === '/foundation-models') {
    let models = catalog();
    const prov = (url.searchParams.get('byProvider') || '').toLowerCase();
    const byOut = (url.searchParams.get('byOutputModality') || '').toUpperCase();
    const byInf = (url.searchParams.get('byInferenceType') || '').toUpperCase();
    if (prov) models = models.filter((x) => x.providerName.toLowerCase().includes(prov));
    if (byOut) models = models.filter((x) => x.outputModalities.includes(byOut));
    if (byInf) models = models.filter((x) => x.inferenceTypesSupported.includes(byInf));
    return out(new Response(JSON.stringify({ modelSummaries: models }), { status: 200, headers: H() }), 'ListFoundationModels');
  }
  // GET /foundation-models/{id} (GetFoundationModel)
  if (method === 'GET' && p.startsWith('/foundation-models/')) {
    const id = decodeURIComponent(p.slice('/foundation-models/'.length));
    const f = catalog().find((x) => x.modelId === id || x.modelArn === id);
    if (!f) return out(err('ResourceNotFoundException', `The provided model identifier is invalid.`, 400), 'GetFoundationModel', id);
    return out(new Response(JSON.stringify({ modelDetails: f }), { status: 200, headers: H() }), 'GetFoundationModel', id);
  }
  // GET /inference-profiles (ListInferenceProfiles)
  if (method === 'GET' && p === '/inference-profiles') {
    const mkp = (name, id, modelId) => ({
      inferenceProfileName: name, inferenceProfileId: id,
      inferenceProfileArn: `arn:aws:bedrock:us-east-1:271943558210:inference-profile/${id}`,
      models: [{ modelArn: `arn:aws:bedrock:us-east-1::foundation-model/${modelId}` }, { modelArn: `arn:aws:bedrock:us-west-2::foundation-model/${modelId}` }],
      status: 'ACTIVE', type: 'SYSTEM_DEFINED',
      createdAt: '2026-10-22T18:04:11.233Z', updatedAt: '2026-10-22T18:04:11.233Z',
    });
    const profs = [
      mkp('US Anthropic Claude Opus 5', 'us.anthropic.claude-opus-5', 'anthropic.claude-opus-5'),
      mkp('US Claude 3.5 Sonnet v2', 'us.anthropic.claude-3-5-sonnet-20241022-v2:0', 'anthropic.claude-3-5-sonnet-20241022-v2:0'),
      mkp('US Nova Lite', 'us.amazon.nova-lite-v1:0', 'amazon.nova-lite-v1:0'),
    ];
    return out(new Response(JSON.stringify({ inferenceProfileSummaries: profs }), { status: 200, headers: H() }), 'ListInferenceProfiles');
  }

  // POST /model/{id}/(converse|converse-stream|invoke|invoke-with-response-stream)
  const rm = p.match(/^\/model\/([^/]+)\/(converse|converse-stream|invoke|invoke-with-response-stream)$/);
  if (rm && method === 'POST') {
    const model = decodeURIComponent(rm[1]);
    const op = rm[2];
    let raw = ''; try { raw = await request.text(); } catch {}
    let body = {}; try { body = JSON.parse(raw || '{}'); } catch {}

    // Anthropic "use case details" gate: real Bedrock 404s these until the form is
    // approved; fire for a deterministic subset so sequencing looks authentic.
    if (model.startsWith('anthropic.') && (model.includes('opus') || model.includes('v2:1'))) {
      return out(err('ResourceNotFoundException', `Could not resolve the foundation model from the provided model identifier. You may need to request access to the model, including submitting use case details, before you can invoke it.`, 404), op.includes('converse') ? 'Converse' : 'InvokeModel', model, raw);
    }
    // InvokeModel live-vs-denied tell: out-of-range max_tokens_to_sample -> ValidationException
    const mts = body.max_tokens_to_sample;
    if (op.startsWith('invoke') && mts != null && (mts < 1 || mts > 1000000)) {
      return out(err('ValidationException', 'Malformed input request: #/max_tokens_to_sample: must have a minimum value of 1 and a maximum value of 1000000, please reformat your input and try again.', 400), 'InvokeModel', model, raw);
    }

    const msgs = toMessages(body);
    const text = await complete(env, base.ip, msgs);
    const itok = Math.max(1, raw.length >> 2);
    const otok = Math.max(1, text.length >> 2);
    const lat = 300 + (itok % 600);

    if (op === 'converse') {
      const resp = new Response(JSON.stringify({
        output: { message: { role: 'assistant', content: [{ text }] } },
        stopReason: 'end_turn',
        usage: { inputTokens: itok, outputTokens: otok, totalTokens: itok + otok, cacheReadInputTokens: 0, cacheWriteInputTokens: 0 },
        metrics: { latencyMs: lat },
        performanceConfig: { latency: 'standard' },
      }), { status: 200, headers: H() });
      return out(resp, 'Converse', model, raw, 'ok');
    }
    if (op === 'converse-stream') {
      const words = (text.match(/\S+\s*/g) || [text]);
      const evs = [esMessage('messageStart', { role: 'assistant' })];
      words.forEach((w, i) => evs.push(esMessage('contentBlockDelta', { contentBlockIndex: 0, delta: { text: w } })));
      evs.push(esMessage('contentBlockStop', { contentBlockIndex: 0 }));
      evs.push(esMessage('messageStop', { stopReason: 'end_turn' }));
      evs.push(esMessage('metadata', { usage: { inputTokens: itok, outputTokens: otok, totalTokens: itok + otok }, metrics: { latencyMs: lat } }));
      const resp = new Response(eventStream(evs), { status: 200, headers: H({ 'Content-Type': 'application/vnd.amazon.eventstream' }) });
      return out(resp, 'ConverseStream', model, raw, 'ok');
    }
    // invoke / invoke-with-response-stream: claude text-completions body
    const invBody = { type: 'completion', completion: ' ' + text, stop_reason: 'stop_sequence', stop: '\n\nHuman:' };
    const invHdr = H({
      'X-Amzn-Bedrock-Input-Token-Count': String(itok),
      'X-Amzn-Bedrock-Output-Token-Count': String(otok),
      'X-Amzn-Bedrock-Invocation-Latency': String(lat),
      'X-Amzn-Bedrock-PerformanceConfig-Latency': 'standard',
    });
    if (op === 'invoke') {
      return out(new Response(JSON.stringify(invBody), { status: 200, headers: invHdr }), 'InvokeModel', model, raw, 'ok');
    }
    // invoke-with-response-stream: eventstream of base64 "chunk" payloads
    const chunk = esMessage('chunk', { bytes: btoa(JSON.stringify(invBody)) });
    const resp = new Response(eventStream([chunk]), { status: 200, headers: H({ 'Content-Type': 'application/vnd.amazon.eventstream', 'X-Amzn-Bedrock-Input-Token-Count': String(itok), 'X-Amzn-Bedrock-Output-Token-Count': String(otok) }) });
    return out(resp, 'InvokeModelWithResponseStream', model, raw, 'ok');
  }

  return null;
}
