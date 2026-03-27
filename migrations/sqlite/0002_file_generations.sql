CREATE TABLE IF NOT EXISTS file_generations (
    workspace_id TEXT COLLATE BINARY NOT NULL CHECK (length(workspace_id) > 0),
    path TEXT COLLATE BINARY NOT NULL CHECK (length(path) > 0),
    last_version INTEGER NOT NULL CHECK (last_version >= 0),
    PRIMARY KEY (workspace_id, path)
);

INSERT OR IGNORE INTO file_generations (workspace_id, path, last_version)
SELECT workspace_id, path, version
FROM files;

UPDATE file_generations
SET last_version = (
    SELECT files.version
    FROM files
    WHERE files.workspace_id = file_generations.workspace_id
      AND files.path = file_generations.path
)
WHERE EXISTS (
    SELECT 1
    FROM files
    WHERE files.workspace_id = file_generations.workspace_id
      AND files.path = file_generations.path
      AND files.version > file_generations.last_version
);
