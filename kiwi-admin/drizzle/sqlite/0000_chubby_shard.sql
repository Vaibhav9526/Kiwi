CREATE TABLE `audit_log` (
	`seq` integer PRIMARY KEY NOT NULL,
	`ts` integer NOT NULL,
	`actor_subject` text,
	`actor_roles` text,
	`org_id` text,
	`action` text NOT NULL,
	`resource` text,
	`outcome` text NOT NULL,
	`request_id` text,
	`details` text,
	`prev_hash` text NOT NULL,
	`entry_hash` text NOT NULL,
	CONSTRAINT "audit_outcome_check" CHECK("audit_log"."outcome" IN ('allowed','denied','error'))
);
--> statement-breakpoint
CREATE TABLE `devices` (
	`id` text PRIMARY KEY NOT NULL,
	`org_id` text NOT NULL,
	`label` text NOT NULL,
	`revoked` integer DEFAULT 0 NOT NULL,
	`revoked_at` integer,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`org_id`) REFERENCES `orgs`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `domains` (
	`org_id` text NOT NULL,
	`domain` text NOT NULL,
	`verified` integer DEFAULT 0 NOT NULL,
	`created_at` integer NOT NULL,
	PRIMARY KEY(`org_id`, `domain`),
	FOREIGN KEY (`org_id`) REFERENCES `orgs`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `mailflow_events` (
	`id` text PRIMARY KEY NOT NULL,
	`org_id` text,
	`direction` text NOT NULL,
	`sender` text NOT NULL,
	`recipient` text NOT NULL,
	`ts` integer NOT NULL,
	`message_id` text,
	`tls_version` text,
	`security_status` text DEFAULT 'unknown' NOT NULL,
	`policy_verdict` text DEFAULT 'unknown' NOT NULL,
	`received_at` integer NOT NULL,
	CONSTRAINT "mailflow_direction_check" CHECK("mailflow_events"."direction" IN ('inbound','outbound')),
	CONSTRAINT "mailflow_policy_verdict_check" CHECK("mailflow_events"."policy_verdict" IN ('allow','warn','block','unknown'))
);
--> statement-breakpoint
CREATE INDEX `idx_mailflow_org_ts` ON `mailflow_events` (`org_id`,`ts`);--> statement-breakpoint
CREATE INDEX `idx_mailflow_recipient` ON `mailflow_events` (`recipient`);--> statement-breakpoint
CREATE TABLE `orgs` (
	`id` text PRIMARY KEY NOT NULL,
	`name` text NOT NULL,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `policies` (
	`id` text PRIMARY KEY NOT NULL,
	`org_id` text NOT NULL,
	`name` text NOT NULL,
	`enabled` integer DEFAULT 1 NOT NULL,
	`min_tls` text,
	`external_recipients` text DEFAULT 'allow' NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`org_id`) REFERENCES `orgs`(`id`) ON UPDATE no action ON DELETE cascade,
	CONSTRAINT "policies_external_recipients_check" CHECK("policies"."external_recipients" IN ('allow','warn','block'))
);
--> statement-breakpoint
CREATE TABLE `policy_domain_rules` (
	`policy_id` text NOT NULL,
	`domain` text NOT NULL,
	`action` text NOT NULL,
	PRIMARY KEY(`policy_id`, `domain`),
	FOREIGN KEY (`policy_id`) REFERENCES `policies`(`id`) ON UPDATE no action ON DELETE cascade,
	CONSTRAINT "policy_domain_rules_action_check" CHECK("policy_domain_rules"."action" IN ('allow','block'))
);
--> statement-breakpoint
CREATE TABLE `user_org_roles` (
	`user_id` text NOT NULL,
	`org_id` text NOT NULL,
	`role` text NOT NULL,
	`granted_at` integer NOT NULL,
	PRIMARY KEY(`user_id`, `org_id`),
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`org_id`) REFERENCES `orgs`(`id`) ON UPDATE no action ON DELETE cascade,
	CONSTRAINT "user_org_roles_role_check" CHECK("user_org_roles"."role" IN ('org_admin','security_admin','viewer'))
);
--> statement-breakpoint
CREATE TABLE `users` (
	`id` text PRIMARY KEY NOT NULL,
	`org_id` text NOT NULL,
	`email` text NOT NULL,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`org_id`) REFERENCES `orgs`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `idx_users_org_email` ON `users` (`org_id`,`email`);