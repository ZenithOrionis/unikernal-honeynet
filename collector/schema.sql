CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    decoy_id TEXT NOT NULL,
    profile TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    suspicious INTEGER NOT NULL DEFAULT 0,
    tags TEXT NOT NULL DEFAULT '[]',
    raw_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_decoy ON events(decoy_id);
CREATE INDEX IF NOT EXISTS idx_events_profile ON events(profile);
CREATE INDEX IF NOT EXISTS idx_events_path ON events(path);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_suspicious ON events(suspicious);

