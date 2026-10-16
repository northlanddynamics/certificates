CREATE TABLE "device_certificate" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" text NOT NULL,
	"enrollment_profile_id" uuid NOT NULL,
	"issuing_ca_id" uuid NOT NULL,
	"serial" text NOT NULL,
	"fingerprint" text NOT NULL,
	"subject" text NOT NULL,
	"subject_alt_names" jsonb NOT NULL,
	"not_before" timestamp with time zone NOT NULL,
	"not_after" timestamp with time zone NOT NULL,
	"certificate_pem" text NOT NULL,
	"device_id" text,
	"transaction_id" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "device_certificate_organization_fingerprint_unique" UNIQUE("organization_id","fingerprint")
);
--> statement-breakpoint
CREATE TABLE "enrollment_profile" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" text NOT NULL,
	"name" text NOT NULL,
	"public_id" text NOT NULL,
	"issuing_ca_id" uuid NOT NULL,
	"validity_days" integer NOT NULL,
	"key_usage" text[] NOT NULL,
	"extended_key_usage" text[] NOT NULL,
	"allowed_key_types" text[] NOT NULL,
	"validator_kind" text NOT NULL,
	"ra_certificate_pem" text NOT NULL,
	"ra_key_secret_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "enrollment_profile_organization_name_unique" UNIQUE("organization_id","name"),
	CONSTRAINT "enrollment_profile_public_id_unique" UNIQUE("public_id"),
	CONSTRAINT "enrollment_profile_id_organization_unique" UNIQUE("id","organization_id"),
	CONSTRAINT "enrollment_profile_validity" CHECK ("enrollment_profile"."validity_days" >= 1)
);
--> statement-breakpoint
ALTER TABLE "device_certificate" ADD CONSTRAINT "device_certificate_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "device_certificate" ADD CONSTRAINT "device_certificate_enrollment_profile_id_organization_id_enrollment_profile_id_organization_id_fk" FOREIGN KEY ("enrollment_profile_id","organization_id") REFERENCES "public"."enrollment_profile"("id","organization_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "device_certificate" ADD CONSTRAINT "device_certificate_issuing_ca_id_organization_id_issuing_ca_id_organization_id_fk" FOREIGN KEY ("issuing_ca_id","organization_id") REFERENCES "public"."issuing_ca"("id","organization_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "enrollment_profile" ADD CONSTRAINT "enrollment_profile_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "enrollment_profile" ADD CONSTRAINT "enrollment_profile_issuing_ca_id_organization_id_issuing_ca_id_organization_id_fk" FOREIGN KEY ("issuing_ca_id","organization_id") REFERENCES "public"."issuing_ca"("id","organization_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "enrollment_profile" ADD CONSTRAINT "enrollment_profile_ra_key_secret_id_organization_id_secret_id_organization_id_fk" FOREIGN KEY ("ra_key_secret_id","organization_id") REFERENCES "public"."secret"("id","organization_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "device_certificate_profile_idx" ON "device_certificate" USING btree ("enrollment_profile_id","created_at");