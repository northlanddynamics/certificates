ALTER TABLE "agent_identity_ca" DISABLE ROW LEVEL SECURITY;--> statement-breakpoint
DROP TABLE "agent_identity_ca" CASCADE;--> statement-breakpoint
-- Agents registered under mTLS (ADR 0005) have no credential, and never will: a value no SHA-256 can equal, already ended, so each registers again.
UPDATE "agent" SET "credential_hash" = 'none:' || "id", "credential_expires_at" = "registered_at" WHERE "credential_hash" IS NULL;--> statement-breakpoint
ALTER TABLE "agent" ALTER COLUMN "credential_hash" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "agent" ALTER COLUMN "credential_expires_at" SET NOT NULL;--> statement-breakpoint
CREATE INDEX "agent_previous_credential_idx" ON "agent" USING btree ("previous_credential_hash");--> statement-breakpoint
ALTER TABLE "agent" DROP COLUMN "identity_serial";--> statement-breakpoint
ALTER TABLE "agent" DROP COLUMN "previous_identity_serial";--> statement-breakpoint
ALTER TABLE "agent" ADD CONSTRAINT "agent_credential_hash_unique" UNIQUE("credential_hash");