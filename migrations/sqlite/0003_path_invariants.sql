DROP TRIGGER IF EXISTS files_path_invariant_insert;
DROP TRIGGER IF EXISTS files_path_invariant_update;

CREATE TRIGGER files_path_invariant_insert
BEFORE INSERT ON files
FOR EACH ROW
WHEN (
    NEW.path = ''
    OR trim(NEW.path, char(9) || char(10) || char(11) || char(12) || char(13) || ' ') <> NEW.path
    OR substr(NEW.path, 1, 1) = '/'
    OR substr(NEW.path, length(NEW.path), 1) = '/'
    OR instr(NEW.path, '\') > 0
    OR instr(NEW.path, '//') > 0
    OR NEW.path = '.'
    OR NEW.path = '..'
    OR NEW.path LIKE './%'
    OR NEW.path LIKE '../%'
    OR NEW.path LIKE '%/./%'
    OR NEW.path LIKE '%/../%'
    OR NEW.path LIKE '%/.'
    OR NEW.path LIKE '%/..'
    OR (
        substr(NEW.path, 2, 1) = ':'
        AND (
            unicode(substr(NEW.path, 1, 1)) BETWEEN 65 AND 90
            OR unicode(substr(NEW.path, 1, 1)) BETWEEN 97 AND 122
        )
    )
)
BEGIN
    SELECT RAISE(ABORT, 'files.path must stay a canonical relative path');
END;

CREATE TRIGGER files_path_invariant_update
BEFORE UPDATE OF path ON files
FOR EACH ROW
WHEN (
    NEW.path = ''
    OR trim(NEW.path, char(9) || char(10) || char(11) || char(12) || char(13) || ' ') <> NEW.path
    OR substr(NEW.path, 1, 1) = '/'
    OR substr(NEW.path, length(NEW.path), 1) = '/'
    OR instr(NEW.path, '\') > 0
    OR instr(NEW.path, '//') > 0
    OR NEW.path = '.'
    OR NEW.path = '..'
    OR NEW.path LIKE './%'
    OR NEW.path LIKE '../%'
    OR NEW.path LIKE '%/./%'
    OR NEW.path LIKE '%/../%'
    OR NEW.path LIKE '%/.'
    OR NEW.path LIKE '%/..'
    OR (
        substr(NEW.path, 2, 1) = ':'
        AND (
            unicode(substr(NEW.path, 1, 1)) BETWEEN 65 AND 90
            OR unicode(substr(NEW.path, 1, 1)) BETWEEN 97 AND 122
        )
    )
)
BEGIN
    SELECT RAISE(ABORT, 'files.path must stay a canonical relative path');
END;
