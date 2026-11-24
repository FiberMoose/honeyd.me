CREATE TABLE IF NOT EXISTS counts (
  day TEXT NOT NULL,
  event TEXT NOT NULL,
  n INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (day, event)
) WITHOUT ROWID;

-- guest book: one row per signed line, plus full submitter metadata for threat intel.
CREATE TABLE IF NOT EXISTS signs (
  ts TEXT NOT NULL, who TEXT NOT NULL, why TEXT NOT NULL, submitted TEXT,
  ip TEXT, country TEXT, asn TEXT, as_org TEXT, ua TEXT,
  referer TEXT, origin TEXT, accept_language TEXT,
  colo TEXT, tls TEXT, http_proto TEXT, path TEXT, method TEXT, headers TEXT
);

-- key-rotation audit: one row per rotation of an edge-stored value (KV write + this row).
CREATE TABLE IF NOT EXISTS key_rotations (
  ts TEXT NOT NULL,
  key_id TEXT NOT NULL
);

-- beacon subdomain hits: one row per request to mcp./k8s.honeyd.me, with the
-- full source so we hold the IP even though the canarytokens ping shows our edge.
CREATE TABLE IF NOT EXISTS canary_hits (
  ts TEXT, host TEXT, path TEXT, method TEXT, beacon TEXT,
  ip TEXT, country TEXT, asn TEXT, as_org TEXT, ua TEXT, referer TEXT, colo TEXT
);

-- full request log for the fake REST API (internal-api.honeyd.me): what the
-- attacker queried, which leaked key + tier, and the request body.
CREATE TABLE IF NOT EXISTS api_hits (
  ts TEXT, host TEXT, method TEXT, path TEXT, query TEXT, tier TEXT, api_key TEXT,
  status INTEGER, ip TEXT, country TEXT, asn TEXT, as_org TEXT, ua TEXT, client TEXT, body TEXT
);

-- statefulness: records the attacker writes, reflected back on later reads.
CREATE TABLE IF NOT EXISTS api_records (
  ts TEXT, record_id TEXT, ip TEXT, data TEXT
);

-- captured LLM prompts: what key-abuse bots try to generate through the fake
-- model gateway (the real intel). source = relay (real model) or fallback.
CREATE TABLE IF NOT EXISTS llm_prompts (
  ts TEXT, ip TEXT, api_key TEXT, model TEXT, source TEXT, messages TEXT
);

-- per-ip + global budget counters for the burner llm relay. strongly consistent
-- (D1, not KV) so a burst from one ip is actually caught and can't starve others.
-- bucket = im:<ip>:<min> | id:<ip>:<day> | gm:<min> | gd:<day>; exp is unix ttl.
CREATE TABLE IF NOT EXISTS llm_rl (
  bucket TEXT PRIMARY KEY, n INTEGER NOT NULL DEFAULT 0, exp INTEGER
);

-- first-party apex log: every bait grab (.env/.git/dump/actuator/phpinfo/
-- graphql/cred-files/gcp/ssh/backups) and every 403 probe, with source.
CREATE TABLE IF NOT EXISTS apex_hits (
  ts TEXT, host TEXT, path TEXT, method TEXT, label TEXT, status INTEGER,
  ip TEXT, country TEXT, asn TEXT, as_org TEXT, ua TEXT
);
