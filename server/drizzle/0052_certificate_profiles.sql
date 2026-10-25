CREATE TABLE "certificate_profile" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" text NOT NULL,
	"name" text NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"issuer_kind" text NOT NULL,
	"acme_ca_id" text,
	"issuing_ca_id" uuid,
	"allowed_key_algorithms" text[] NOT NULL,
	"validity_days" integer,
	"renewal_mode" text DEFAULT 'automatic' NOT NULL,
	"renewal_days_before_expiry" integer DEFAULT 30 NOT NULL,
	"default_team_id" text,
	"enabled" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "certificate_profile_organization_name_unique" UNIQUE("organization_id","name"),
	CONSTRAINT "certificate_profile_id_organization_unique" UNIQUE("id","organization_id"),
	CONSTRAINT "certificate_profile_issuer_kind" CHECK (("certificate_profile"."issuer_kind" = 'acme' and "certificate_profile"."acme_ca_id" is not null and "certificate_profile"."issuing_ca_id" is null) or ("certificate_profile"."issuer_kind" = 'private_ca' and "certificate_profile"."issuing_ca_id" is not null and "certificate_profile"."acme_ca_id" is null)),
	CONSTRAINT "certificate_profile_validity" CHECK ("certificate_profile"."validity_days" is null or ("certificate_profile"."issuer_kind" = 'private_ca' and "certificate_profile"."validity_days" >= 1)),
	CONSTRAINT "certificate_profile_key_algorithms" CHECK (cardinality("certificate_profile"."allowed_key_algorithms") >= 1),
	CONSTRAINT "certificate_profile_renewal_mode" CHECK ("certificate_profile"."renewal_mode" in ('automatic', 'manual')),
	CONSTRAINT "certificate_profile_renewal_days" CHECK ("certificate_profile"."renewal_days_before_expiry" between 1 and 365)
);
--> statement-breakpoint
ALTER TABLE "certificate_profile" ADD CONSTRAINT "certificate_profile_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "certificate_profile" ADD CONSTRAINT "certificate_profile_default_team_id_team_id_fk" FOREIGN KEY ("default_team_id") REFERENCES "public"."team"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "certificate_profile" ADD CONSTRAINT "certificate_profile_issuing_ca_id_organization_id_issuing_ca_id_organization_id_fk" FOREIGN KEY ("issuing_ca_id","organization_id") REFERENCES "public"."issuing_ca"("id","organization_id") ON DELETE no action ON UPDATE no action;