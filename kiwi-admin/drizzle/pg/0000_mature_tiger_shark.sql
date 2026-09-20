CREATE TABLE "audit_log" (
	"seq" bigint PRIMARY KEY NOT NULL,
	"ts" bigint NOT NULL,
	"actor_subject" text,
	"actor_roles" text,
	"org_id" text,
	"action" text NOT NULL,
	"resource" text,
	"outcome" text NOT NULL,
	"request_id" text,
	"details" text,
	"prev_hash" text NOT NULL,
	"entry_hash" text NOT NULL,
	CONSTRAINT "audit_outcome_check" CHECK ("audit_log"."outcome" IN ('allowed','denied','error'))
);
--> statement-breakpoint
CREATE TABLE "devices" (
	"id" text PRIMARY KEY NOT NULL,
	"org_id" text NOT NULL,
	"label" text NOT NULL,
	"revoked" boolean DEFAULT false NOT NULL,
	"revoked_at" bigint,
	"created_at" bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE "domains" (
	"org_id" text NOT NULL,
	"domain" text NOT NULL,
	"verified" boolean DEFAULT false NOT NULL,
	"created_at" bigint NOT NULL,
	CONSTRAINT "domains_org_id_domain_pk" PRIMARY KEY("org_id","domain")
);
--> statement-breakpoint
CREATE TABLE "mailflow_events" (
	"id" text PRIMARY KEY NOT NULL,
	"org_id" text,
	"direction" text NOT NULL,
	"sender" text NOT NULL,
	"recipient" text NOT NULL,
	"ts" bigint NOT NULL,
	"message_id" text,
	"tls_version" text,
	"security_status" text DEFAULT 'unknown' NOT NULL,
	"policy_verdict" text DEFAULT 'unknown' NOT NULL,
	"received_at" bigint NOT NULL,
	CONSTRAINT "mailflow_direction_check" CHECK ("mailflow_events"."direction" IN ('inbound','outbound')),
	CONSTRAINT "mailflow_policy_verdict_check" CHECK ("mailflow_events"."policy_verdict" IN ('allow','warn','block','unknown'))
);
--> statement-breakpoint
CREATE TABLE "orgs" (
	"id" text PRIMARY KEY NOT NULL,
	"name" text NOT NULL,
	"created_at" bigint NOT NULL
);
--> statement-breakpoint
CREATE TABLE "policies" (
	"id" text PRIMARY KEY NOT NULL,
	"org_id" text NOT NULL,
	"name" text NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"min_tls" text,
	"external_recipients" text DEFAULT 'allow' NOT NULL,
	"created_at" bigint NOT NULL,
	"updated_at" bigint NOT NULL,
	CONSTRAINT "policies_external_recipients_check" CHECK ("policies"."external_recipients" IN ('allow','warn','block'))
);
--> statement-breakpoint
CREATE TABLE "policy_domain_rules" (
	"policy_id" text NOT NULL,
	"domain" text NOT NULL,
	"action" text NOT NULL,
	CONSTRAINT "policy_domain_rules_policy_id_domain_pk" PRIMARY KEY("policy_id","domain"),
	CONSTRAINT "policy_domain_rules_action_check" CHECK ("policy_domain_rules"."action" IN ('allow','block'))
);
--> statement-breakpoint
CREATE TABLE "user_org_roles" (
	"user_id" text NOT NULL,
	"org_id" text NOT NULL,
	"role" text NOT NULL,
	"granted_at" bigint NOT NULL,
	CONSTRAINT "user_org_roles_user_id_org_id_pk" PRIMARY KEY("user_id","org_id"),
	CONSTRAINT "user_org_roles_role_check" CHECK ("user_org_roles"."role" IN ('org_admin','security_admin','viewer'))
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" text PRIMARY KEY NOT NULL,
	"org_id" text NOT NULL,
	"email" text NOT NULL,
	"created_at" bigint NOT NULL
);
--> statement-breakpoint
ALTER TABLE "devices" ADD CONSTRAINT "devices_org_id_orgs_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."orgs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "domains" ADD CONSTRAINT "domains_org_id_orgs_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."orgs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policies" ADD CONSTRAINT "policies_org_id_orgs_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."orgs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policy_domain_rules" ADD CONSTRAINT "policy_domain_rules_policy_id_policies_id_fk" FOREIGN KEY ("policy_id") REFERENCES "public"."policies"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_org_roles" ADD CONSTRAINT "user_org_roles_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_org_roles" ADD CONSTRAINT "user_org_roles_org_id_orgs_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."orgs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "users" ADD CONSTRAINT "users_org_id_orgs_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."orgs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "idx_mailflow_org_ts" ON "mailflow_events" USING btree ("org_id","ts");--> statement-breakpoint
CREATE INDEX "idx_mailflow_recipient" ON "mailflow_events" USING btree ("recipient");--> statement-breakpoint
CREATE INDEX "idx_users_org_email" ON "users" USING btree ("org_id","email");