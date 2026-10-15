-- A Private CA's validity limits, and the validity a Managed Certificate on one chooses (and a Name Change gives it). A
-- Private CA made before them gets 397 days for both; a Managed Certificate made before them chooses none, and gets
-- its Private CA's default.
ALTER TABLE "managed_certificate" ADD COLUMN "validity_days" integer;--> statement-breakpoint
ALTER TABLE "name_change" ADD COLUMN "validity_days" integer;--> statement-breakpoint
ALTER TABLE "private_ca" ADD COLUMN "max_validity_days" integer DEFAULT 397 NOT NULL;--> statement-breakpoint
ALTER TABLE "private_ca" ADD COLUMN "default_validity_days" integer DEFAULT 397 NOT NULL;--> statement-breakpoint
ALTER TABLE "managed_certificate" ADD CONSTRAINT "managed_certificate_validity" CHECK ("managed_certificate"."validity_days" is null or ("managed_certificate"."issuer_kind" = 'private_ca' and "managed_certificate"."validity_days" >= 1));--> statement-breakpoint
ALTER TABLE "private_ca" ADD CONSTRAINT "private_ca_validity" CHECK ("private_ca"."default_validity_days" between 1 and "private_ca"."max_validity_days");