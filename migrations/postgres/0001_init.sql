CREATE TABLE IF NOT EXISTS files (
    workspace_id TEXT COLLATE "C" NOT NULL CHECK (length(workspace_id) > 0),
    path TEXT COLLATE "C" NOT NULL CHECK (length(path) > 0),
    content TEXT NOT NULL,
    size_bytes BIGINT NOT NULL
        CHECK (size_bytes >= 0)
        CHECK (size_bytes = octet_length(content)),
    version BIGINT NOT NULL CHECK (version >= 1),
    created_at_ms BIGINT NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms BIGINT NOT NULL CHECK (updated_at_ms >= created_at_ms),
    metadata_json JSONB,
    PRIMARY KEY (workspace_id, path)
);

CREATE INDEX IF NOT EXISTS files_workspace_updated_at_ms_idx
    ON files (workspace_id, updated_at_ms);
