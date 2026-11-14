-- Yappitron v1 schema, part 4: encrypted attachments.
--
-- The files themselves live on disk (YAP_BLOB_DIR). This table only says which conversation a
-- file belongs to (who may download it) and who uploaded it (quota, right to delete). There are
-- no file names, types or timestamps: those are inside the end-to-end encrypted messages.
CREATE TABLE blobs (
    id              UUID   PRIMARY KEY,
    conversation_id UUID   NOT NULL REFERENCES conversations (id) ON DELETE CASCADE,
    account_id      UUID   NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    size            BIGINT NOT NULL CHECK (size > 0)
);
CREATE INDEX blobs_account ON blobs (account_id);
CREATE INDEX blobs_conversation ON blobs (conversation_id);
