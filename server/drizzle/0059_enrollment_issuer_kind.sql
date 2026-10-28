ALTER TABLE "device_certificate" ALTER COLUMN "issuing_ca_id" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "enrollment_profile" ALTER COLUMN "issuing_ca_id" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "device_certificate" ADD COLUMN "issuer_kind" text DEFAULT 'private_ca' NOT NULL;--> statement-breakpoint
ALTER TABLE "enrollment_profile" ADD COLUMN "issuer_kind" text DEFAULT 'private_ca' NOT NULL;--> statement-breakpoint
ALTER TABLE "device_certificate" ADD CONSTRAINT "device_certificate_issuer_kind" CHECK ("device_certificate"."issuer_kind" = 'private_ca' and "device_certificate"."issuing_ca_id" is not null);--> statement-breakpoint
ALTER TABLE "enrollment_profile" ADD CONSTRAINT "enrollment_profile_issuer_kind" CHECK ("enrollment_profile"."issuer_kind" = 'private_ca' and "enrollment_profile"."issuing_ca_id" is not null);