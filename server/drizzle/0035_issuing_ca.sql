-- A Private CA becomes a root and the Issuing CAs under it (`issuing_ca`), and a Managed Certificate's or a Certificate's
-- Private CA kind of issuer names an Issuing CA. Each existing Private CA's Issuing CA moves to its own row, with the
-- Private CA's id as its id: so a Managed Certificate's and a Certificate's `private_ca_id` already holds its Issuing CA's
-- id, and the column is only renamed. No Certificate row is updated, so the Certificate's immutability trigger does not
-- fire. The root keeps its status `active`: until now the status was the Issuing CA's, which it keeps.
CREATE TABLE "issuing_ca" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" text NOT NULL,
	"private_ca_id" uuid NOT NULL,
	"subject" text NOT NULL,
	"certificate_pem" text,
	"key" text NOT NULL,
	"status" text NOT NULL,
	"permitted_exact_names" text[] DEFAULT '{}' NOT NULL,
	"permitted_zones" text[] DEFAULT '{}' NOT NULL,
	"max_validity_days" integer DEFAULT 397 NOT NULL,
	"default_validity_days" integer DEFAULT 397 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "issuing_ca_private_ca_subject_unique" UNIQUE("private_ca_id","subject"),
	CONSTRAINT "issuing_ca_id_organization_unique" UNIQUE("id","organization_id"),
	CONSTRAINT "issuing_ca_status" CHECK ("issuing_ca"."status" in ('awaiting_signature', 'active', 'retired', 'revoked')),
	CONSTRAINT "issuing_ca_signed" CHECK ("issuing_ca"."status" = 'awaiting_signature' or "issuing_ca"."certificate_pem" is not null),
	CONSTRAINT "issuing_ca_validity" CHECK ("issuing_ca"."default_validity_days" between 1 and "issuing_ca"."max_validity_days")
);
--> statement-breakpoint
ALTER TABLE "issuing_ca" ADD CONSTRAINT "issuing_ca_private_ca_id_organization_id_private_ca_id_organization_id_fk" FOREIGN KEY ("private_ca_id","organization_id") REFERENCES "public"."private_ca"("id","organization_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
INSERT INTO "issuing_ca" ("id", "organization_id", "private_ca_id", "subject", "certificate_pem", "key", "status", "permitted_exact_names", "permitted_zones", "max_validity_days", "default_validity_days", "created_at")
	SELECT "id", "organization_id", "id", "subject", "issuing_certificate_pem", "issuing_key", "status", "permitted_exact_names", "permitted_zones", "max_validity_days", "default_validity_days", "created_at" FROM "private_ca";--> statement-breakpoint
ALTER TABLE "certificate" DROP CONSTRAINT "certificate_issuer_kind";--> statement-breakpoint
ALTER TABLE "managed_certificate" DROP CONSTRAINT "managed_certificate_issuer_kind";--> statement-breakpoint
ALTER TABLE "certificate" DROP CONSTRAINT "certificate_private_ca_id_organization_id_private_ca_id_organization_id_fk";--> statement-breakpoint
ALTER TABLE "managed_certificate" DROP CONSTRAINT "managed_certificate_private_ca_id_organization_id_private_ca_id_organization_id_fk";--> statement-breakpoint
ALTER TABLE "certificate" RENAME COLUMN "private_ca_id" TO "issuing_ca_id";--> statement-breakpoint
ALTER TABLE "managed_certificate" RENAME COLUMN "private_ca_id" TO "issuing_ca_id";--> statement-breakpoint
ALTER TABLE "certificate" ADD CONSTRAINT "certificate_issuing_ca_id_organization_id_issuing_ca_id_organization_id_fk" FOREIGN KEY ("issuing_ca_id","organization_id") REFERENCES "public"."issuing_ca"("id","organization_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "managed_certificate" ADD CONSTRAINT "managed_certificate_issuing_ca_id_organization_id_issuing_ca_id_organization_id_fk" FOREIGN KEY ("issuing_ca_id","organization_id") REFERENCES "public"."issuing_ca"("id","organization_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "certificate" ADD CONSTRAINT "certificate_issuer_kind" CHECK (("certificate"."issuer_kind" = 'acme' and "certificate"."environment" is not null and "certificate"."acme_account_id" is not null and "certificate"."issuing_ca_id" is null) or ("certificate"."issuer_kind" = 'private_ca' and "certificate"."issuing_ca_id" is not null and "certificate"."environment" is null and "certificate"."acme_account_id" is null));--> statement-breakpoint
ALTER TABLE "managed_certificate" ADD CONSTRAINT "managed_certificate_issuer_kind" CHECK (("managed_certificate"."issuer_kind" = 'acme' and "managed_certificate"."environment" is not null and "managed_certificate"."issuing_ca_id" is null) or ("managed_certificate"."issuer_kind" = 'private_ca' and "managed_certificate"."issuing_ca_id" is not null and "managed_certificate"."environment" is null));--> statement-breakpoint
ALTER TABLE "private_ca" DROP CONSTRAINT "private_ca_signed";--> statement-breakpoint
ALTER TABLE "private_ca" DROP CONSTRAINT "private_ca_validity";--> statement-breakpoint
ALTER TABLE "private_ca" DROP CONSTRAINT "private_ca_status";--> statement-breakpoint
UPDATE "private_ca" SET "status" = 'active';--> statement-breakpoint
ALTER TABLE "private_ca" ADD CONSTRAINT "private_ca_status" CHECK ("private_ca"."status" in ('active', 'revoked'));--> statement-breakpoint
ALTER TABLE "private_ca" DROP COLUMN "subject";--> statement-breakpoint
ALTER TABLE "private_ca" DROP COLUMN "issuing_certificate_pem";--> statement-breakpoint
ALTER TABLE "private_ca" DROP COLUMN "issuing_key";--> statement-breakpoint
ALTER TABLE "private_ca" DROP COLUMN "permitted_exact_names";--> statement-breakpoint
ALTER TABLE "private_ca" DROP COLUMN "permitted_zones";--> statement-breakpoint
ALTER TABLE "private_ca" DROP COLUMN "max_validity_days";--> statement-breakpoint
ALTER TABLE "private_ca" DROP COLUMN "default_validity_days";
