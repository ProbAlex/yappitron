-- Yappitron v1 schema (M1: accounts and authentication).
--
-- Deliberately absent: created_at/updated_at/last_login, IP addresses, plaintext emails.
-- The only timestamps are short-lived expiries on rows that are swept away.

CREATE TABLE accounts (
    id            UUID  PRIMARY KEY,
    username      TEXT  NOT NULL UNIQUE,   -- canonical (lowercase) form
    email_hmac    BYTEA NOT NULL UNIQUE,   -- HMAC of the normalized email; never the address
    opaque_record BYTEA NOT NULL           -- OPAQUE registration record; the server never sees the password
);

-- One-time codes sent by email (signup and password reset).
CREATE TABLE email_codes (
    email_hmac BYTEA       NOT NULL,
    purpose    TEXT        NOT NULL CHECK (purpose IN ('signup', 'reset')),
    code_mac   BYTEA       NOT NULL,
    attempts   INT         NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (email_hmac, purpose)
);

-- Proof that an email was verified; spent when the signup/reset finishes.
CREATE TABLE tickets (
    token_hash BYTEA       PRIMARY KEY,
    email_hmac BYTEA       NOT NULL,
    purpose    TEXT        NOT NULL CHECK (purpose IN ('signup', 'reset')),
    expires_at TIMESTAMPTZ NOT NULL
);

-- OPAQUE server login state between login/start and login/finish. Kept in the database
-- (not in memory) so any gateway node can finish a login another node started.
CREATE TABLE login_states (
    id         UUID        PRIMARY KEY,
    account_id UUID,                      -- NULL when the username does not exist
    username   TEXT        NOT NULL,      -- OPAQUE client identifier, re-checked at finish
    state      BYTEA       NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE sessions (
    token_hash BYTEA       PRIMARY KEY,
    account_id UUID        NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL
);

-- Server-wide secrets that must be stable across restarts and shared by all gateway nodes.
-- Values are sealed (AEAD) under a key derived from YAP_SERVER_SECRET, which is NOT stored here.
CREATE TABLE server_config (
    key   TEXT  PRIMARY KEY,
    value BYTEA NOT NULL
);
