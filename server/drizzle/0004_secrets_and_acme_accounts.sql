CREATE TABLE "acme_account" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" text NOT NULL,
	"environment" text NOT NULL,
	"account_url" text NOT NULL,
	"contact_email" text,
	"secret_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "acme_account_organization_environment_unique" UNIQUE("organization_id","environment")
);
--> statement-breakpoint
CREATE TABLE "organization_data_key" (
	"organization_id" text PRIMARY KEY NOT NULL,
	"wrapped_key" "bytea" NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "secret" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" text NOT NULL,
	"ciphertext" "bytea" NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "secret_id_organization_unique" UNIQUE("id","organization_id")
);
--> statement-breakpoint
ALTER TABLE "acme_account" ADD CONSTRAINT "acme_account_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "acme_account" ADD CONSTRAINT "acme_account_secret_id_organization_id_secret_id_organization_id_fk" FOREIGN KEY ("secret_id","organization_id") REFERENCES "public"."secret"("id","organization_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "organization_data_key" ADD CONSTRAINT "organization_data_key_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "secret" ADD CONSTRAINT "secret_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE no action ON UPDATE no action;