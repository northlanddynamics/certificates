CREATE TABLE "adcs_ca" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" text NOT NULL,
	"name" text NOT NULL,
	"config_string" text NOT NULL,
	"ca_certificate_pem" text NOT NULL,
	"chain_pem" text[] NOT NULL,
	"cdp_urls" text[] NOT NULL,
	"discovered_at" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone NOT NULL,
	CONSTRAINT "adcs_ca_organization_name_unique" UNIQUE("organization_id","name"),
	CONSTRAINT "adcs_ca_organization_config_string_unique" UNIQUE("organization_id","config_string"),
	CONSTRAINT "adcs_ca_id_organization_unique" UNIQUE("id","organization_id")
);
--> statement-breakpoint
CREATE TABLE "adcs_ca_agent" (
	"organization_id" text NOT NULL,
	"adcs_ca_id" uuid NOT NULL,
	"agent_id" uuid NOT NULL,
	CONSTRAINT "adcs_ca_agent_adcs_ca_id_agent_id_pk" PRIMARY KEY("adcs_ca_id","agent_id")
);
--> statement-breakpoint
CREATE TABLE "adcs_template" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" text NOT NULL,
	"adcs_ca_id" uuid NOT NULL,
	"name" text NOT NULL,
	"oid" text NOT NULL,
	"display_name" text NOT NULL,
	"extended_key_usages" text[] NOT NULL,
	"validity_days" integer NOT NULL,
	"minimum_key_size" integer NOT NULL,
	"key_algorithms" text[] NOT NULL,
	"manager_approval" boolean NOT NULL,
	"subject_from_request" boolean NOT NULL,
	"enrollable" boolean NOT NULL,
	"published" boolean NOT NULL,
	CONSTRAINT "adcs_template_ca_name_unique" UNIQUE("adcs_ca_id","name"),
	CONSTRAINT "adcs_template_id_organization_unique" UNIQUE("id","organization_id")
);
--> statement-breakpoint
ALTER TABLE "adcs_ca" ADD CONSTRAINT "adcs_ca_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "adcs_ca_agent" ADD CONSTRAINT "adcs_ca_agent_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "adcs_ca_agent" ADD CONSTRAINT "adcs_ca_agent_adcs_ca_id_organization_id_adcs_ca_id_organization_id_fk" FOREIGN KEY ("adcs_ca_id","organization_id") REFERENCES "public"."adcs_ca"("id","organization_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "adcs_ca_agent" ADD CONSTRAINT "adcs_ca_agent_agent_id_organization_id_agent_id_organization_id_fk" FOREIGN KEY ("agent_id","organization_id") REFERENCES "public"."agent"("id","organization_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "adcs_template" ADD CONSTRAINT "adcs_template_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "adcs_template" ADD CONSTRAINT "adcs_template_adcs_ca_id_organization_id_adcs_ca_id_organization_id_fk" FOREIGN KEY ("adcs_ca_id","organization_id") REFERENCES "public"."adcs_ca"("id","organization_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "adcs_ca_agent_agent_idx" ON "adcs_ca_agent" USING btree ("agent_id");