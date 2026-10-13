CREATE TABLE "deployment_script" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" text NOT NULL,
	"name" text NOT NULL,
	"interpreter" text NOT NULL,
	"created_at" timestamp with time zone NOT NULL,
	CONSTRAINT "deployment_script_organization_name_unique" UNIQUE("organization_id","name"),
	CONSTRAINT "deployment_script_id_organization_unique" UNIQUE("id","organization_id"),
	CONSTRAINT "deployment_script_interpreter" CHECK ("deployment_script"."interpreter" in ('bash', 'powershell'))
);
--> statement-breakpoint
CREATE TABLE "deployment_script_version" (
	"script_id" uuid NOT NULL,
	"organization_id" text NOT NULL,
	"version" integer NOT NULL,
	"hash" text NOT NULL,
	"content" text NOT NULL,
	"size" integer NOT NULL,
	"uploaded_by_id" text NOT NULL,
	"uploaded_by_email" text NOT NULL,
	"uploaded_at" timestamp with time zone NOT NULL,
	CONSTRAINT "deployment_script_version_script_id_version_pk" PRIMARY KEY("script_id","version"),
	CONSTRAINT "deployment_script_version_hash_unique" UNIQUE("script_id","hash")
);
--> statement-breakpoint
ALTER TABLE "deployment_script" ADD CONSTRAINT "deployment_script_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "deployment_script_version" ADD CONSTRAINT "deployment_script_version_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "deployment_script_version" ADD CONSTRAINT "deployment_script_version_script_id_organization_id_deployment_script_id_organization_id_fk" FOREIGN KEY ("script_id","organization_id") REFERENCES "public"."deployment_script"("id","organization_id") ON DELETE no action ON UPDATE no action;