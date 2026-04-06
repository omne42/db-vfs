CREATE OR REPLACE FUNCTION db_vfs_is_literal_workspace_id(candidate TEXT)
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT
        candidate IS NOT NULL
        AND candidate <> ''
        AND octet_length(candidate) <= 256
        AND candidate !~ '[[:space:]]'
        AND candidate !~ E'[\\x00-\\x1F\\x7F]'
        AND strpos(candidate, '/') = 0
        AND strpos(candidate, E'\\') = 0
        AND strpos(candidate, ':') = 0
        AND strpos(candidate, '..') = 0
        AND strpos(candidate, '*') = 0;
$$;

ALTER TABLE files DROP CONSTRAINT IF EXISTS files_workspace_id_literal_check;
ALTER TABLE files
    ADD CONSTRAINT files_workspace_id_literal_check
    CHECK (db_vfs_is_literal_workspace_id(workspace_id));
