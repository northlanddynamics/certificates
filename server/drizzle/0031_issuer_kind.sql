-- A Managed Certificate's issuer, and the issuer a Certificate came from, is a kind (issuer.ts). Every row so far is of the
-- ACME kind, with its environment and ACME account as they were. Adding a column with a default updates no row, so the
-- Certificate's immutability trigger does not fire.
ALTER TABLE "certificate" ADD COLUMN "issuer_kind" text DEFAULT 'acme' NOT NULL;--> statement-breakpoint
ALTER TABLE "managed_certificate" ADD COLUMN "issuer_kind" text DEFAULT 'acme' NOT NULL;--> statement-breakpoint
ALTER TABLE "certificate" ADD CONSTRAINT "certificate_issuer_kind" CHECK ("certificate"."issuer_kind" in ('acme'));--> statement-breakpoint
ALTER TABLE "managed_certificate" ADD CONSTRAINT "managed_certificate_issuer_kind" CHECK ("managed_certificate"."issuer_kind" in ('acme'));