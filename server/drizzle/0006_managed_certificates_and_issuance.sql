CREATE TABLE "certificate" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" text NOT NULL,
	"managed_certificate_id" uuid NOT NULL,
	"fingerprint" text NOT NULL,
	"serial" text NOT NULL,
	"not_before" timestamp with time zone NOT NULL,
	"not_after" timestamp with time zone NOT NULL,
	"names" text[] NOT NULL,
	"chain_pem" text NOT NULL,
	"ca" text NOT NULL,
	"environment" text NOT NULL,
	"acme_account_id" uuid NOT NULL,
	"issued_at" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "certificate_organization_fingerprint_unique" UNIQUE("organization_id","fingerprint")
);
--> statement-breakpoint
CREATE TABLE "issuance" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" text NOT NULL,
	"managed_certificate_id" uuid NOT NULL,
	"status" text NOT NULL,
	"requested_by_id" text NOT NULL,
	"requested_by_email" text NOT NULL,
	"failure_code" text,
	"failure_message" text,
	"certificate_id" uuid,
	"started_at" timestamp with time zone NOT NULL,
	"finished_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "managed_certificate" ADD COLUMN "names" text[] NOT NULL;--> statement-breakpoint
ALTER TABLE "managed_certificate" ADD COLUMN "key_algorithm" text NOT NULL;--> statement-breakpoint
ALTER TABLE "managed_certificate" ADD COLUMN "key_custody" text NOT NULL;--> statement-breakpoint
ALTER TABLE "managed_certificate" ADD COLUMN "environment" text NOT NULL;--> statement-breakpoint
ALTER TABLE "managed_certificate" ADD COLUMN "csr" text NOT NULL;--> statement-breakpoint
ALTER TABLE "managed_certificate" ADD CONSTRAINT "managed_certificate_id_organization_unique" UNIQUE("id","organization_id");--> statement-breakpoint
ALTER TABLE "certificate" ADD CONSTRAINT "certificate_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "certificate" ADD CONSTRAINT "certificate_acme_account_id_acme_account_id_fk" FOREIGN KEY ("acme_account_id") REFERENCES "public"."acme_account"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "certificate" ADD CONSTRAINT "certificate_managed_certificate_id_organization_id_managed_certificate_id_organization_id_fk" FOREIGN KEY ("managed_certificate_id","organization_id") REFERENCES "public"."managed_certificate"("id","organization_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "issuance" ADD CONSTRAINT "issuance_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "issuance" ADD CONSTRAINT "issuance_managed_certificate_id_organization_id_managed_certificate_id_organization_id_fk" FOREIGN KEY ("managed_certificate_id","organization_id") REFERENCES "public"."managed_certificate"("id","organization_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "certificate_managed_certificate_idx" ON "certificate" USING btree ("managed_certificate_id","created_at");--> statement-breakpoint
CREATE INDEX "issuance_managed_certificate_idx" ON "issuance" USING btree ("managed_certificate_id","created_at");--> statement-breakpoint
CREATE UNIQUE INDEX "issuance_one_running_per_managed_certificate" ON "issuance" USING btree ("managed_certificate_id") WHERE "issuance"."status" = 'running';
