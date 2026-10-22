CREATE TABLE IF NOT EXISTS operations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL, -- 'SIGN' or 'VERIFY'
    signature_level TEXT,
    packaging TEXT,
    digest TEXT,
    used_tsa BOOLEAN DEFAULT 0,
    used_ocsp BOOLEAN DEFAULT 0,
    used_crl BOOLEAN DEFAULT 0,
    used_keystore BOOLEAN DEFAULT 0,
    success BOOLEAN,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);