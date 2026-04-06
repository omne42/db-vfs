DROP TRIGGER IF EXISTS files_workspace_id_invariant_insert;
DROP TRIGGER IF EXISTS files_workspace_id_invariant_update;

CREATE TRIGGER files_workspace_id_invariant_insert
BEFORE INSERT ON files
FOR EACH ROW
WHEN (
    NEW.workspace_id = ''
    OR length(CAST(NEW.workspace_id AS BLOB)) > 256
    OR instr(NEW.workspace_id, char(0)) > 0
    OR instr(NEW.workspace_id, ' ') > 0
    OR instr(NEW.workspace_id, char(9)) > 0
    OR instr(NEW.workspace_id, char(10)) > 0
    OR instr(NEW.workspace_id, char(11)) > 0
    OR instr(NEW.workspace_id, char(12)) > 0
    OR instr(NEW.workspace_id, char(13)) > 0
    OR instr(NEW.workspace_id, '/') > 0
    OR instr(NEW.workspace_id, '\') > 0
    OR instr(NEW.workspace_id, ':') > 0
    OR instr(NEW.workspace_id, '..') > 0
    OR instr(NEW.workspace_id, '*') > 0
)
BEGIN
    SELECT RAISE(ABORT, 'files.workspace_id must stay a literal workspace identifier');
END;

CREATE TRIGGER files_workspace_id_invariant_update
BEFORE UPDATE OF workspace_id ON files
FOR EACH ROW
WHEN (
    NEW.workspace_id = ''
    OR length(CAST(NEW.workspace_id AS BLOB)) > 256
    OR instr(NEW.workspace_id, char(0)) > 0
    OR instr(NEW.workspace_id, ' ') > 0
    OR instr(NEW.workspace_id, char(9)) > 0
    OR instr(NEW.workspace_id, char(10)) > 0
    OR instr(NEW.workspace_id, char(11)) > 0
    OR instr(NEW.workspace_id, char(12)) > 0
    OR instr(NEW.workspace_id, char(13)) > 0
    OR instr(NEW.workspace_id, '/') > 0
    OR instr(NEW.workspace_id, '\') > 0
    OR instr(NEW.workspace_id, ':') > 0
    OR instr(NEW.workspace_id, '..') > 0
    OR instr(NEW.workspace_id, '*') > 0
)
BEGIN
    SELECT RAISE(ABORT, 'files.workspace_id must stay a literal workspace identifier');
END;
