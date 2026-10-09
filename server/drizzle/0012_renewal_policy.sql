ALTER TABLE "issuance" ALTER COLUMN "requested_by_id" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "issuance" ALTER COLUMN "requested_by_email" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "managed_certificate" ADD COLUMN "renewal_mode" text DEFAULT 'automatic' NOT NULL;--> statement-breakpoint
ALTER TABLE "managed_certificate" ADD COLUMN "renewal_days_before_expiry" integer DEFAULT 30 NOT NULL;--> statement-breakpoint
ALTER TABLE "managed_certificate" ADD CONSTRAINT "managed_certificate_renewal_mode" CHECK ("managed_certificate"."renewal_mode" in ('automatic', 'manual'));--> statement-breakpoint
ALTER TABLE "managed_certificate" ADD CONSTRAINT "managed_certificate_renewal_days" CHECK ("managed_certificate"."renewal_days_before_expiry" between 1 and 365);