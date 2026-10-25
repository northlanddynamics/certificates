ALTER TABLE "acme_account" RENAME COLUMN "environment" TO "acme_ca_id";--> statement-breakpoint
ALTER TABLE "certificate" RENAME COLUMN "environment" TO "acme_ca_id";--> statement-breakpoint
ALTER TABLE "managed_certificate" RENAME COLUMN "environment" TO "acme_ca_id";--> statement-breakpoint
-- The environments were Let's Encrypt's: each becomes the built-in ACME CA of the same name (acme-cas.ts).
UPDATE "acme_account" SET "acme_ca_id" = 'letsencrypt-' || "acme_ca_id";--> statement-breakpoint
-- A Certificate is immutable (0007); only this rename of its issuer reference is let through, and the guard is back before
-- the migration commits.
ALTER TABLE "certificate" DISABLE TRIGGER "certificate_no_update_delete";--> statement-breakpoint
UPDATE "certificate" SET "acme_ca_id" = 'letsencrypt-' || "acme_ca_id" WHERE "acme_ca_id" IS NOT NULL;--> statement-breakpoint
ALTER TABLE "certificate" ENABLE TRIGGER "certificate_no_update_delete";--> statement-breakpoint
UPDATE "managed_certificate" SET "acme_ca_id" = 'letsencrypt-' || "acme_ca_id" WHERE "acme_ca_id" IS NOT NULL;--> statement-breakpoint
ALTER TABLE "acme_account" DROP CONSTRAINT "acme_account_organization_environment_unique";--> statement-breakpoint
ALTER TABLE "certificate" DROP CONSTRAINT "certificate_issuer_kind";--> statement-breakpoint
ALTER TABLE "managed_certificate" DROP CONSTRAINT "managed_certificate_issuer_kind";--> statement-breakpoint
ALTER TABLE "acme_account" ADD CONSTRAINT "acme_account_organization_acme_ca_unique" UNIQUE("organization_id","acme_ca_id");--> statement-breakpoint
ALTER TABLE "certificate" ADD CONSTRAINT "certificate_issuer_kind" CHECK (("certificate"."issuer_kind" = 'acme' and "certificate"."acme_ca_id" is not null and "certificate"."acme_account_id" is not null and "certificate"."issuing_ca_id" is null) or ("certificate"."issuer_kind" = 'private_ca' and "certificate"."issuing_ca_id" is not null and "certificate"."acme_ca_id" is null and "certificate"."acme_account_id" is null));--> statement-breakpoint
ALTER TABLE "managed_certificate" ADD CONSTRAINT "managed_certificate_issuer_kind" CHECK (("managed_certificate"."issuer_kind" = 'acme' and "managed_certificate"."acme_ca_id" is not null and "managed_certificate"."issuing_ca_id" is null) or ("managed_certificate"."issuer_kind" = 'private_ca' and "managed_certificate"."issuing_ca_id" is not null and "managed_certificate"."acme_ca_id" is null));