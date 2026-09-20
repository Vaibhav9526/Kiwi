DROP INDEX "idx_users_org_email";--> statement-breakpoint
CREATE UNIQUE INDEX "idx_users_org_email" ON "users" USING btree ("org_id","email");