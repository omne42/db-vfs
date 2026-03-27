CREATE TABLE IF NOT EXISTS file_generations (
    workspace_id TEXT COLLATE "C" NOT NULL CHECK (length(workspace_id) > 0),
    path TEXT COLLATE "C" NOT NULL CHECK (length(path) > 0),
    last_version BIGINT NOT NULL CHECK (last_version >= 0),
    PRIMARY KEY (workspace_id, path)
);

INSERT INTO file_generations (workspace_id, path, last_version)
SELECT workspace_id, path, version
FROM files
ON CONFLICT (workspace_id, path) DO UPDATE SET
    last_version = EXCLUDED.last_version
WHERE EXCLUDED.last_version > file_generations.last_version;
