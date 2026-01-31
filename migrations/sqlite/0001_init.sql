CREATE TABLE IF NOT EXISTS files (
    workspace_id TEXT NOT NULL,
    path TEXT NOT NULL,
    content TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    version INTEGER NOT NULL,
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    metadata_json TEXT,
    PRIMARY KEY (workspace_id, path)
);

CREATE INDEX IF NOT EXISTS files_workspace_updated_at_ms_idx
    ON files (workspace_id, updated_at_ms);

