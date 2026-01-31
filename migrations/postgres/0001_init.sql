CREATE TABLE IF NOT EXISTS files (
    workspace_id TEXT COLLATE "C" NOT NULL,
    path TEXT COLLATE "C" NOT NULL,
    content TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    version BIGINT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    metadata_json TEXT,
    PRIMARY KEY (workspace_id, path)
);

CREATE INDEX IF NOT EXISTS files_workspace_updated_at_ms_idx
    ON files (workspace_id, updated_at_ms);

