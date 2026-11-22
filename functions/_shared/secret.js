// Runtime config values resolved at the edge. Values are supplied by the Pages
// KV binding `BAIT` (keys: aws_akia, aws_secret, bedrock_key) and are not stored
// in this repo. If the binding or a key is absent, the value resolves to empty
// and the caller omits it. Set values in the honeyd-bait KV namespace to populate.

async function fromKv(env, key) {
  try {
    const v = env && env.BAIT ? await env.BAIT.get(key) : null;
    if (v && typeof v === 'string' && v.trim()) return v.trim();
  } catch { /* no binding, no permission, or over quota */ }
  return null;
}

export async function secret(env, key) {
  return (await fromKv(env, key)) || '';
}
