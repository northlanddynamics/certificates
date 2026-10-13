ALTER TABLE "agent" DROP CONSTRAINT "agent_os";--> statement-breakpoint
ALTER TABLE "agent" ADD COLUMN "credential_hash" text;--> statement-breakpoint
ALTER TABLE "agent" ADD COLUMN "credential_expires_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "agent" ADD COLUMN "previous_credential_hash" text;--> statement-breakpoint
ALTER TABLE "agent" ADD COLUMN "previous_credential_expires_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "agent" ADD CONSTRAINT "agent_os" CHECK ("agent"."os" in ('linux', 'windows', 'macos'));