CREATE TABLE "adcs_request" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" text NOT NULL,
	"adcs_ca_id" uuid NOT NULL,
	"template_id" uuid NOT NULL,
	"issuance_id" uuid NOT NULL,
	"csr" text NOT NULL,
	"status" text NOT NULL,
	"agent_id" uuid,
	"work_item_id" uuid,
	"submitted_at" timestamp with time zone,
	"tried_agent_ids" uuid[] DEFAULT '{}' NOT NULL,
	"adcs_request_id" text,
	"certificate_pem" text,
	"created_at" timestamp with time zone NOT NULL,
	"finished_at" timestamp with time zone,
	CONSTRAINT "adcs_request_status" CHECK ("adcs_request"."status" in ('waiting', 'submitted', 'issued', 'failed')),
	CONSTRAINT "adcs_request_submitted" CHECK ("adcs_request"."status" <> 'submitted' or ("adcs_request"."agent_id" is not null and "adcs_request"."work_item_id" is not null and "adcs_request"."submitted_at" is not null)),
	CONSTRAINT "adcs_request_issued" CHECK ("adcs_request"."status" <> 'issued' or ("adcs_request"."adcs_request_id" is not null and "adcs_request"."certificate_pem" is not null))
);
--> statement-breakpoint
ALTER TABLE "certificate" DROP CONSTRAINT "certificate_issuer_kind";--> statement-breakpoint
ALTER TABLE "managed_certificate" DROP CONSTRAINT "managed_certificate_issuer_kind";--> statement-breakpoint
ALTER TABLE "adcs_ca" ADD COLUMN "permitted_exact_names" text[];--> statement-breakpoint
ALTER TABLE "adcs_ca" ADD COLUMN "permitted_zones" text[];--> statement-breakpoint
ALTER TABLE "certificate" ADD COLUMN "adcs_ca_id" uuid;--> statement-breakpoint
ALTER TABLE "certificate" ADD COLUMN "adcs_template_id" uuid;--> statement-breakpoint
ALTER TABLE "certificate" ADD COLUMN "adcs_request_id" text;--> statement-breakpoint
ALTER TABLE "managed_certificate" ADD COLUMN "adcs_ca_id" uuid;--> statement-breakpoint
ALTER TABLE "managed_certificate" ADD COLUMN "adcs_template_id" uuid;--> statement-breakpoint
ALTER TABLE "adcs_template" ADD CONSTRAINT "adcs_template_id_ca_unique" UNIQUE("id","adcs_ca_id");--> statement-breakpoint
ALTER TABLE "adcs_request" ADD CONSTRAINT "adcs_request_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "adcs_request" ADD CONSTRAINT "adcs_request_issuance_id_issuance_id_fk" FOREIGN KEY ("issuance_id") REFERENCES "public"."issuance"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "adcs_request" ADD CONSTRAINT "adcs_request_adcs_ca_id_organization_id_adcs_ca_id_organization_id_fk" FOREIGN KEY ("adcs_ca_id","organization_id") REFERENCES "public"."adcs_ca"("id","organization_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "adcs_request" ADD CONSTRAINT "adcs_request_template_id_adcs_ca_id_adcs_template_id_adcs_ca_id_fk" FOREIGN KEY ("template_id","adcs_ca_id") REFERENCES "public"."adcs_template"("id","adcs_ca_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "adcs_request_issuance_unique" ON "adcs_request" USING btree ("issuance_id");--> statement-breakpoint
CREATE INDEX "adcs_request_open_idx" ON "adcs_request" USING btree ("status") WHERE "adcs_request"."status" in ('waiting', 'submitted');--> statement-breakpoint
ALTER TABLE "certificate" ADD CONSTRAINT "certificate_adcs_ca_id_organization_id_adcs_ca_id_organization_id_fk" FOREIGN KEY ("adcs_ca_id","organization_id") REFERENCES "public"."adcs_ca"("id","organization_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "certificate" ADD CONSTRAINT "certificate_adcs_template_id_adcs_ca_id_adcs_template_id_adcs_ca_id_fk" FOREIGN KEY ("adcs_template_id","adcs_ca_id") REFERENCES "public"."adcs_template"("id","adcs_ca_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "managed_certificate" ADD CONSTRAINT "managed_certificate_adcs_ca_id_organization_id_adcs_ca_id_organization_id_fk" FOREIGN KEY ("adcs_ca_id","organization_id") REFERENCES "public"."adcs_ca"("id","organization_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "managed_certificate" ADD CONSTRAINT "managed_certificate_adcs_template_id_adcs_ca_id_adcs_template_id_adcs_ca_id_fk" FOREIGN KEY ("adcs_template_id","adcs_ca_id") REFERENCES "public"."adcs_template"("id","adcs_ca_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "adcs_ca" ADD CONSTRAINT "adcs_ca_permitted_names" CHECK (("adcs_ca"."permitted_exact_names" is null) = ("adcs_ca"."permitted_zones" is null));--> statement-breakpoint
ALTER TABLE "certificate" ADD CONSTRAINT "certificate_issuer_kind" CHECK (("certificate"."issuer_kind" = 'acme' and "certificate"."acme_ca_id" is not null and "certificate"."acme_account_id" is not null and "certificate"."issuing_ca_id" is null and "certificate"."adcs_ca_id" is null) or ("certificate"."issuer_kind" = 'private_ca' and "certificate"."issuing_ca_id" is not null and "certificate"."acme_ca_id" is null and "certificate"."acme_account_id" is null and "certificate"."adcs_ca_id" is null) or ("certificate"."issuer_kind" = 'adcs' and "certificate"."adcs_ca_id" is not null and "certificate"."adcs_template_id" is not null and "certificate"."adcs_request_id" is not null and "certificate"."acme_ca_id" is null and "certificate"."acme_account_id" is null and "certificate"."issuing_ca_id" is null));--> statement-breakpoint
ALTER TABLE "managed_certificate" ADD CONSTRAINT "managed_certificate_issuer_kind" CHECK (("managed_certificate"."issuer_kind" = 'acme' and "managed_certificate"."acme_ca_id" is not null and "managed_certificate"."issuing_ca_id" is null and "managed_certificate"."adcs_ca_id" is null and "managed_certificate"."adcs_template_id" is null) or ("managed_certificate"."issuer_kind" = 'private_ca' and "managed_certificate"."issuing_ca_id" is not null and "managed_certificate"."acme_ca_id" is null and "managed_certificate"."adcs_ca_id" is null and "managed_certificate"."adcs_template_id" is null) or ("managed_certificate"."issuer_kind" = 'adcs' and "managed_certificate"."adcs_ca_id" is not null and "managed_certificate"."adcs_template_id" is not null and "managed_certificate"."acme_ca_id" is null and "managed_certificate"."issuing_ca_id" is null));