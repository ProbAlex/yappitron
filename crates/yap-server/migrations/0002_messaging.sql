-- Yappitron v1 schema, part 2 (M2/M3: devices, conversations, the encrypted message log).
--
-- Still absent on purpose: message timestamps and sender ids. Clients put the real time
-- inside the encrypted payload; the server keeps only an ordering number.

-- A device is one installation of the app. Each device is its own MLS member.
CREATE TABLE devices (
    id         UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    name       TEXT NOT NULL            -- user-visible label, e.g. "Firefox on Linux"
);
CREATE INDEX devices_account ON devices (account_id);

-- A login session is bound to one device once the client registers or attaches it.
ALTER TABLE sessions ADD COLUMN device_id UUID REFERENCES devices (id) ON DELETE SET NULL;

-- One-time MLS key packages; handed out once each so others can add this device to a group.
CREATE TABLE key_packages (
    id        BIGSERIAL PRIMARY KEY,
    device_id UUID  NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    data      BYTEA NOT NULL
);
CREATE INDEX key_packages_device ON key_packages (device_id);

-- The conversation id doubles as the MLS group id (16 bytes), so everyone agrees on it.
CREATE TABLE conversations (
    id       UUID   PRIMARY KEY,
    last_seq BIGINT NOT NULL DEFAULT 0
);

-- 'invited' = a message request the account has not accepted yet.
CREATE TABLE conversation_members (
    conversation_id UUID NOT NULL REFERENCES conversations (id) ON DELETE CASCADE,
    account_id      UUID NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    state           TEXT NOT NULL CHECK (state IN ('joined', 'invited', 'declined')),
    PRIMARY KEY (conversation_id, account_id)
);
CREATE INDEX conversation_members_account ON conversation_members (account_id);

-- The ordered, encrypted log. kind: 0 = MLS commit, 1 = application message.
CREATE TABLE messages (
    conversation_id UUID     NOT NULL REFERENCES conversations (id) ON DELETE CASCADE,
    seq             BIGINT   NOT NULL,
    kind            SMALLINT NOT NULL CHECK (kind IN (0, 1)),
    data            BYTEA    NOT NULL,
    PRIMARY KEY (conversation_id, seq)
);

-- An MLS Welcome waiting for one device to join a conversation. join_seq is the last log
-- entry already reflected in that Welcome; the device processes entries after it.
CREATE TABLE welcomes (
    id              BIGSERIAL PRIMARY KEY,
    device_id       UUID   NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    conversation_id UUID   NOT NULL REFERENCES conversations (id) ON DELETE CASCADE,
    join_seq        BIGINT NOT NULL,
    data            BYTEA  NOT NULL
);
CREATE INDEX welcomes_device ON welcomes (device_id);

-- A row here means "this device is an MLS member of this conversation". last_seq is how far
-- it has processed the log; it drives redelivery after being offline.
CREATE TABLE device_cursors (
    device_id       UUID   NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    conversation_id UUID   NOT NULL REFERENCES conversations (id) ON DELETE CASCADE,
    last_seq        BIGINT NOT NULL,
    PRIMARY KEY (device_id, conversation_id)
);
