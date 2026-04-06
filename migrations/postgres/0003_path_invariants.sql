CREATE OR REPLACE FUNCTION db_vfs_is_canonical_path(candidate TEXT)
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT
        candidate IS NOT NULL
        AND candidate <> ''
        AND candidate !~ '^[[:space:]]'
        AND candidate !~ '[[:space:]]$'
        AND candidate !~ '^[A-Za-z]:'
        AND strpos(candidate, E'\\') = 0
        AND strpos(candidate, '//') = 0
        AND left(candidate, 1) <> '/'
        AND right(candidate, 1) <> '/'
        AND candidate !~ '(^|/)\.\.?(/|$)'
        AND candidate !~ E'[\\x00-\\x1F\\x7F]';
$$;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'files'
          AND column_name = 'metadata_json'
    ) THEN
        EXECUTE 'ALTER TABLE files DROP COLUMN metadata_json';
    END IF;
END $$;

ALTER TABLE files DROP CONSTRAINT IF EXISTS files_path_canonical_check;
ALTER TABLE files
    ADD CONSTRAINT files_path_canonical_check
    CHECK (db_vfs_is_canonical_path(path));
