// Runtime config values resolved at the edge. Values are supplied by the Pages
// KV binding `BAIT` (keys: aws_akia, aws_secret, bedrock_key) and are not stored
// in this repo. If the binding or a key is absent, the value resolves to empty
// and the caller omits it. Set values in the honeyd-bait KV namespace to populate.

const _kv = new Map(); // key -> { v, exp }; per-isolate cache, short TTL
const KV_TTL_MS = 60000;
async function fromKv(env, key) {
  const now = Date.now();
  const c = _kv.get(key);
  if (c && c.exp > now) return c.v;
  let out = null;
  try {
    const v = env && env.BAIT ? await env.BAIT.get(key) : null;
    if (v && typeof v === 'string' && v.trim()) out = v.trim();
  } catch { /* no binding, no permission, or over quota */ }
  _kv.set(key, { v: out, exp: now + KV_TTL_MS });
  return out;
}

export async function secret(env, key) {
  return (await fromKv(env, key)) || '';
}
