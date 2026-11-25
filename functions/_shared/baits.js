// Fake BAIT key values live in KV (key `bait_keys`, one JSON blob), not in the
// repo. They are already public (served in the leak files), but keeping them out
// of git means no secret-shaped literal sits in the public source: GitHub secret
// scanners stay quiet, nothing reads as "our stuff", and the bait is rotatable
// without a commit. Injected at request time, like the real canary secrets.
//
// Shape of the KV value (JSON):
//   { "records": "...", "admin": "...", "vault": "...", "mcp": "...", "k8s": "...",
//     "db": "...", "mail": "...", "app": "...", "session_jwt": "...", "passphrase": "..." }
import { secret } from './secret.js';

const EMPTY = { records: '', admin: '', vault: '', mcp: '', k8s: '', db: '', mail: '', app: '', sessionJwt: '', passphrase: '' };

export async function baits(env) {
  try {
    const raw = await secret(env, 'bait_keys');
    if (!raw) return { ...EMPTY };
    const o = JSON.parse(raw);
    return { records: o.records || '', admin: o.admin || '', vault: o.vault || '', mcp: o.mcp || '', k8s: o.k8s || '', db: o.db || '', mail: o.mail || '', app: o.app || '', sessionJwt: o.session_jwt || '', passphrase: o.passphrase || '' };
  } catch { return { ...EMPTY }; }
}

// Map leaked bait key value -> tier, built from the KV-loaded values. Used so the
// fake API can tell how deep a presented key reaches (records < admin < vault).
export function keyTiers(b) {
  const t = {};
  if (b.records) t[b.records] = 'records';
  if (b.admin) t[b.admin] = 'admin';
  if (b.vault) t[b.vault] = 'vault';
  if (b.mcp) t[b.mcp] = 'records';
  return t;
}
