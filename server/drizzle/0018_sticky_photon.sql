CREATE TABLE "agent" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" text NOT NULL,
	"host_name" text NOT NULL,
	"os" text NOT NULL,
	"arch" text NOT NULL,
	"version" text NOT NULL,
	"identity_serial" text NOT NULL,
	"previous_identity_serial" text,
	"registered_at" timestamp with time zone NOT NULL,
	"last_contact_at" timestamp with time zone NOT NULL,
	"revoked_at" timestamp with time zone,
	"revoked_by_id" text,
	"revoked_by_email" text,
	CONSTRAINT "agent_id_organization_unique" UNIQUE("id","organization_id"),
	CONSTRAINT "agent_os" CHECK ("agent"."os" in ('linux', 'windows')),
	CONSTRAINT "agent_arch" CHECK ("agent"."arch" in ('amd64', 'arm64'))
);
--> statement-breakpoint
CREATE TABLE "agent_identity_ca" (
	"id" integer PRIMARY KEY DEFAULT 1 NOT NULL,
	"certificate_pem" text NOT NULL,
	"wrapped_key" "bytea" NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "agent_identity_ca_singleton" CHECK ("agent_identity_ca"."id" = 1)
);
--> statement-breakpoint
CREATE TABLE "agent_registration_token" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" text NOT NULL,
	"token_hash" text NOT NULL,
	"created_by_id" text NOT NULL,
	"created_by_email" text NOT NULL,
	"created_at" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"used_at" timestamp with time zone,
	"agent_id" uuid,
	CONSTRAINT "agent_registration_token_token_hash_unique" UNIQUE("token_hash")
);
--> statement-breakpoint
ALTER TABLE "agent" ADD CONSTRAINT "agent_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_registration_token" ADD CONSTRAINT "agent_registration_token_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_registration_token" ADD CONSTRAINT "agent_registration_token_agent_id_organization_id_agent_id_organization_id_fk" FOREIGN KEY ("agent_id","organization_id") REFERENCES "public"."agent"("id","organization_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "agent_org_idx" ON "agent" USING btree ("organization_id","registered_at");