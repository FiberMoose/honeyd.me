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
