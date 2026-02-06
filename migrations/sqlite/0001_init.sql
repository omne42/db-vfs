CREATE TABLE IF NOT EXISTS files (
    workspace_id TEXT COLLATE BINARY NOT NULL CHECK (length(workspace_id) > 0),
    path TEXT COLLATE BINARY NOT NULL CHECK (length(path) > 0),
    content TEXT NOT NULL,
    size_bytes INTEGER NOT NULL
        CHECK (size_bytes >= 0)
        CHECK (size_bytes = length(CAST(content AS BLOB))),
    version INTEGER NOT NULL CHECK (version >= 1),
    created_at_ms INTEGER NOT NULL
        DEFAULT (CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER))
        CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL
        DEFAULT (CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER))
        CHECK (updated_at_ms >= created_at_ms),
    metadata_json TEXT CHECK (metadata_json IS NULL OR json_valid(metadata_json)),
    PRIMARY KEY (workspace_id, path)
);

CREATE INDEX IF NOT EXISTS files_workspace_updated_at_ms_idx
    ON files (workspace_id, updated_at_ms);
