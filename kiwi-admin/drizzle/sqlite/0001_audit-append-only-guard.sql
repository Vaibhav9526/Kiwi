-- DB-level append-only guard for audit_log (admin-api.md §7).
-- Blocks UPDATE and DELETE from ANY connection, including raw SQL from the
-- service process. Honest limit: a file-write holder can DROP TRIGGER first,
-- so hash-chain verification on read remains the detection layer.
CREATE TRIGGER `audit_log_no_update`
BEFORE UPDATE ON `audit_log`
BEGIN
  SELECT RAISE(ABORT, 'audit_log is append-only: UPDATE rejected');
END;
--> statement-breakpoint
CREATE TRIGGER `audit_log_no_delete`
BEFORE DELETE ON `audit_log`
BEGIN
  SELECT RAISE(ABORT, 'audit_log is append-only: DELETE rejected');
END;
