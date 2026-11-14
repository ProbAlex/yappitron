-- Multi-device: device approval, history archive, recovery key.
--
-- A device is 'approved' (a full MLS member that receives messages), 'pending' (registered on
-- an existing account and waiting for one of that account's approved devices to let it in) or
-- 'revoked'. The first device of an account is approved automatically.
ALTER TABLE devices
    ADD COLUMN status   TEXT  NOT NULL DEFAULT 'approved'
        CHECK (status IN ('pending', 'approved', 'revoked')),
    -- X25519 public key a pending device publishes so an approved device can seal secrets to it
    ADD COLUMN link_pub BYTEA;

-- What an approving device hands to the device it approved (sealed to the new device's link
-- key, so the server cannot read it). Picked up once and deleted.
CREATE TABLE link_bundles (
    device_id UUID  PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
    data      BYTEA NOT NULL
);

-- The encrypted history archive. MLS forward secrecy means a new device cannot decrypt old
-- messages, so every device also seals each message it reads under the account's history key
-- (which the server never sees) and uploads it here. One row per (account, conversation, seq);
-- devices of the same account upload identical rows, so duplicates are ignored.
CREATE TABLE archive (
    account_id      UUID   NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    conversation_id UUID   NOT NULL REFERENCES conversations (id) ON DELETE CASCADE,
    seq             BIGINT NOT NULL,
    data            BYTEA  NOT NULL,
    PRIMARY KEY (account_id, conversation_id, seq)
);

-- The history key wrapped by the recovery key (so someone who lost every device can still read
-- history), and a hash of a token derived from the recovery key (so the server can check the
-- recovery key without ever seeing it).
CREATE TABLE account_keys (
    account_id         UUID  PRIMARY KEY REFERENCES accounts (id) ON DELETE CASCADE,
    wrapped_hist_key   BYTEA NOT NULL,
    recovery_auth_hash BYTEA NOT NULL
);
