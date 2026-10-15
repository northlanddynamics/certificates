-- Private CAs (private-ca.ts), and the Private CA kind of issuer: a Managed Certificate's or a Certificate's issuer is an
-- ACME account's environment or a Private CA, never both. Every row so far is of the ACME kind and keeps its values, so
-- the checks hold for them; dropping NOT NULL updates no row, so the Certificate's immutability trigger does not fire.
CREATE TABLE "private_ca" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" text NOT NULL,
	"name" text NOT NULL,
	"kind" text NOT NULL,
	"status" text NOT NULL,
	"key_algorithm" text NOT NULL,
	"subject" text NOT NULL,
	"root_certificate_pem" text,
	"root_key" text,
	"issuing_certificate_pem" text,
	"issuing_key" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "private_ca_organization_name_unique" UNIQUE("organization_id","name"),
	CONSTRAINT "private_ca_id_organization_unique" UNIQUE("id","organization_id"),
	CONSTRAINT "private_ca_kind" CHECK ("private_ca"."kind" in ('platform_root', 'organization_root')),
	CONSTRAINT "private_ca_status" CHECK ("private_ca"."status" in ('awaiting_signature', 'active', 'retired', 'revoked')),
	CONSTRAINT "private_ca_platform_root" CHECK ("private_ca"."kind" <> 'platform_root' or ("private_ca"."root_certificate_pem" is not null and "private_ca"."root_key" is not null)),
	CONSTRAINT "private_ca_signed" CHECK ("private_ca"."status" = 'awaiting_signature' or "private_ca"."issuing_certificate_pem" is not null)
);
--> statement-breakpoint
ALTER TABLE "certificate" DROP CONSTRAINT "certificate_issuer_kind";--> statement-breakpoint
ALTER TABLE "managed_certificate" DROP CONSTRAINT "managed_certificate_issuer_kind";--> statement-breakpoint
ALTER TABLE "certificate" ALTER COLUMN "environment" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "certificate" ALTER COLUMN "acme_account_id" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "managed_certificate" ALTER COLUMN "environment" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "certificate" ADD COLUMN "private_ca_id" uuid;--> statement-breakpoint
ALTER TABLE "managed_certificate" ADD COLUMN "private_ca_id" uuid;--> statement-breakpoint
ALTER TABLE "private_ca" ADD CONSTRAINT "private_ca_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "certificate" ADD CONSTRAINT "certificate_private_ca_id_organization_id_private_ca_id_organization_id_fk" FOREIGN KEY ("private_ca_id","organization_id") REFERENCES "public"."private_ca"("id","organization_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "managed_certificate" ADD CONSTRAINT "managed_certificate_private_ca_id_organization_id_private_ca_id_organization_id_fk" FOREIGN KEY ("private_ca_id","organization_id") REFERENCES "public"."private_ca"("id","organization_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "certificate" ADD CONSTRAINT "certificate_issuer_kind" CHECK (("certificate"."issuer_kind" = 'acme' and "certificate"."environment" is not null and "certificate"."acme_account_id" is not null and "certificate"."private_ca_id" is null) or ("certificate"."issuer_kind" = 'private_ca' and "certificate"."private_ca_id" is not null and "certificate"."environment" is null and "certificate"."acme_account_id" is null));--> statement-breakpoint
ALTER TABLE "managed_certificate" ADD CONSTRAINT "managed_certificate_issuer_kind" CHECK (("managed_certificate"."issuer_kind" = 'acme' and "managed_certificate"."environment" is not null and "managed_certificate"."private_ca_id" is null) or ("managed_certificate"."issuer_kind" = 'private_ca' and "managed_certificate"."private_ca_id" is not null and "managed_certificate"."environment" is null));