-- DB-level append-only guard for audit_log (admin-api.md §7).
-- Blocks UPDATE and DELETE from ANY connection, including raw SQL from the
-- service process. Honest limit: a file/superuser holder can DROP TRIGGER
-- first, so hash-chain verification on read remains the detection layer.
CREATE OR REPLACE FUNCTION audit_log_reject_write() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only: % rejected', TG_OP;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;
--> statement-breakpoint
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON "audit_log" FOR EACH ROW EXECUTE FUNCTION audit_log_reject_write();
--> statement-breakpoint
CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON "audit_log" FOR EACH ROW EXECUTE FUNCTION audit_log_reject_write();
