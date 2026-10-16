ALTER TABLE "enrollment_profile" ADD COLUMN "enabled" boolean DEFAULT true NOT NULL;--> statement-breakpoint
ALTER TABLE "enrollment_profile" ADD COLUMN "retention_days" integer DEFAULT 365 NOT NULL;--> statement-breakpoint
CREATE INDEX "device_certificate_expiry_idx" ON "device_certificate" USING btree ("enrollment_profile_id","not_after");--> statement-breakpoint
ALTER TABLE "enrollment_profile" ADD CONSTRAINT "enrollment_profile_retention" CHECK ("enrollment_profile"."retention_days" >= 0);