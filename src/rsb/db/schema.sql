CREATE TABLE IF NOT EXISTS schema_meta (
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS operators (
    telegram_id INTEGER PRIMARY KEY,
    username TEXT,
    is_active INTEGER NOT NULL DEFAULT 1,
    totp_secret TEXT,
    totp_confirmed_at TEXT,
    auth_expires_at TEXT,
    created_at TEXT NOT NULL,
    last_seen_at TEXT
);

CREATE TABLE IF NOT EXISTS access_requests (
    telegram_id INTEGER PRIMARY KEY,
    username TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL,
    decided_at TEXT,
    decided_by INTEGER
);

CREATE INDEX IF NOT EXISTS idx_access_status ON access_requests(status);

CREATE TABLE IF NOT EXISTS enrollment_tokens (
    token_hash TEXT PRIMARY KEY,
    label TEXT,
    created_by INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    used_device_id TEXT
);

CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    hostname TEXT,
    os_name TEXT,
    os_version TEXT,
    owner_telegram_id INTEGER,
    secret_encrypted TEXT NOT NULL,
    capabilities TEXT NOT NULL DEFAULT '["shell"]',
    status TEXT NOT NULL DEFAULT 'offline',
    created_at TEXT NOT NULL,
    last_seen_at TEXT,
    revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id),
    operator_id INTEGER NOT NULL,
    state TEXT NOT NULL,
    purpose TEXT,
    requested_capabilities TEXT NOT NULL DEFAULT '["shell"]',
    capabilities TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    approved_at TEXT,
    denied_at TEXT,
    closed_at TEXT,
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS session_accounts (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(id),
    username TEXT NOT NULL UNIQUE,
    token_hash TEXT NOT NULL,
    capabilities TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS access_grants (
    device_id TEXT NOT NULL REFERENCES devices(id),
    operator_id INTEGER NOT NULL,
    capabilities TEXT NOT NULL,
    granted_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (device_id, operator_id)
);

CREATE TABLE IF NOT EXISTS commands (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    operator_id INTEGER NOT NULL,
    command TEXT NOT NULL,
    exit_code INTEGER,
    output TEXT,
    truncated INTEGER NOT NULL DEFAULT 0,
    started_at TEXT NOT NULL,
    finished_at TEXT
);

CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    actor_type TEXT NOT NULL,
    actor_id TEXT,
    action TEXT NOT NULL,
    device_id TEXT,
    session_id TEXT,
    detail TEXT
);

CREATE INDEX IF NOT EXISTS idx_devices_owner ON devices(owner_telegram_id);
CREATE INDEX IF NOT EXISTS idx_sessions_device_state ON sessions(device_id, state);
CREATE INDEX IF NOT EXISTS idx_sessions_operator_state ON sessions(operator_id, state);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_accounts_session ON session_accounts(session_id);
CREATE INDEX IF NOT EXISTS idx_accounts_token ON session_accounts(token_hash);
CREATE INDEX IF NOT EXISTS idx_commands_session ON commands(session_id, id);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts);
CREATE INDEX IF NOT EXISTS idx_enrollment_expires ON enrollment_tokens(expires_at);
