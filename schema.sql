CREATE TABLE IF NOT EXISTS counts (
  day TEXT NOT NULL,
  event TEXT NOT NULL,
  n INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (day, event)
) WITHOUT ROWID;

-- guest book: one row per signed line. no ip, no ua, no cookie — ts + who + why is the whole row.
CREATE TABLE IF NOT EXISTS signs (
  ts TEXT NOT NULL,
  who TEXT NOT NULL,
  why TEXT NOT NULL
);

-- key-rotation audit: one row per rotation of an edge-stored value (KV write + this row).
CREATE TABLE IF NOT EXISTS key_rotations (
  ts TEXT NOT NULL,
  key_id TEXT NOT NULL
);
