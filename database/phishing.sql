-- =====================================================================
-- phishing.sql
-- Schema for the CyberPhish application.
-- Compatible with SQLite (used by app.py) and easily portable to
-- MySQL/PostgreSQL with minor type adjustments (noted in comments).
-- =====================================================================

-- Users table: stores login credentials (passwords are stored as
-- salted hashes by app.py via werkzeug.security, never in plain text).
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,   -- MySQL: INT AUTO_INCREMENT PRIMARY KEY
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'analyst',      -- 'admin' | 'analyst'
    created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Scan history: one row per URL checked, either via single-URL lookup
-- or as part of a bulk CSV upload.
CREATE TABLE IF NOT EXISTS scan_history (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL,
    url           TEXT NOT NULL,
    prediction    TEXT NOT NULL,        -- 'phishing' | 'legitimate'
    confidence    REAL NOT NULL,        -- model probability, 0.0 - 1.0
    source        TEXT NOT NULL DEFAULT 'manual',  -- 'manual' | 'upload'
    batch_id      TEXT,                 -- groups rows from the same CSV upload
    scanned_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Uploaded files log: tracks CSV files dropped into uploads/
CREATE TABLE IF NOT EXISTS uploads (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL,
    batch_id      TEXT NOT NULL UNIQUE,
    filename      TEXT NOT NULL,
    row_count     INTEGER NOT NULL DEFAULT 0,
    phishing_count INTEGER NOT NULL DEFAULT 0,
    uploaded_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Helpful indexes for the dashboard/report queries
CREATE INDEX IF NOT EXISTS idx_scan_history_user ON scan_history (user_id);
CREATE INDEX IF NOT EXISTS idx_scan_history_batch ON scan_history (batch_id);
CREATE INDEX IF NOT EXISTS idx_scan_history_prediction ON scan_history (prediction);

-- Seed a default administrator account.
-- Username: admin   Password: admin123
-- (password_hash below corresponds to werkzeug's pbkdf2:sha256 for "admin123";
--  app.py will re-seed this automatically on first run if the table is empty,
--  so this INSERT is optional / for reference when using a real MySQL server.)
-- INSERT INTO users (username, password_hash, role)
-- VALUES ('admin', 'pbkdf2:sha256:...', 'admin');
