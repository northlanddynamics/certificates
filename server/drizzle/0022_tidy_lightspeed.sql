CREATE TABLE "deployment" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" text NOT NULL,
	"managed_certificate_id" uuid NOT NULL,
	"agent_id" uuid NOT NULL,
	"script_id" uuid NOT NULL,
	"script_version" integer NOT NULL,
	"created_by_id" text NOT NULL,
	"created_by_email" text NOT NULL,
	"key_failure" text,
	"created_at" timestamp with time zone NOT NULL,
	CONSTRAINT "deployment_id_organization_unique" UNIQUE("id","organization_id")
);
--> statement-breakpoint
CREATE TABLE "deployment_run" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" text NOT NULL,
	"deployment_id" uuid NOT NULL,
	"certificate_id" uuid NOT NULL,
	"trigger" text NOT NULL,
	"status" text NOT NULL,
	"script_version" integer NOT NULL,
	"script_hash" text NOT NULL,
	"started_at" timestamp with time zone NOT NULL,
	"finished_at" timestamp with time zone NOT NULL,
	"exit_code" integer,
	"output" text NOT NULL,
	"output_truncated" boolean NOT NULL,
	"created_at" timestamp with time zone NOT NULL,
	CONSTRAINT "deployment_run_status" CHECK ("deployment_run"."status" in ('succeeded', 'failed')),
	CONSTRAINT "deployment_run_trigger" CHECK ("deployment_run"."trigger" in ('issuance', 'rerun'))
);
--> statement-breakpoint
ALTER TABLE "managed_certificate" ALTER COLUMN "csr" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "deployment" ADD CONSTRAINT "deployment_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "deployment" ADD CONSTRAINT "deployment_managed_certificate_id_organization_id_managed_certificate_id_organization_id_fk" FOREIGN KEY ("managed_certificate_id","organization_id") REFERENCES "public"."managed_certificate"("id","organization_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "deployment" ADD CONSTRAINT "deployment_agent_id_organization_id_agent_id_organization_id_fk" FOREIGN KEY ("agent_id","organization_id") REFERENCES "public"."agent"("id","organization_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "deployment" ADD CONSTRAINT "deployment_script_id_script_version_deployment_script_version_script_id_version_fk" FOREIGN KEY ("script_id","script_version") REFERENCES "public"."deployment_script_version"("script_id","version") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "deployment" ADD CONSTRAINT "deployment_script_id_organization_id_deployment_script_id_organization_id_fk" FOREIGN KEY ("script_id","organization_id") REFERENCES "public"."deployment_script"("id","organization_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "deployment_run" ADD CONSTRAINT "deployment_run_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "deployment_run" ADD CONSTRAINT "deployment_run_certificate_id_certificate_id_fk" FOREIGN KEY ("certificate_id") REFERENCES "public"."certificate"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "deployment_run" ADD CONSTRAINT "deployment_run_deployment_id_organization_id_deployment_id_organization_id_fk" FOREIGN KEY ("deployment_id","organization_id") REFERENCES "public"."deployment"("id","organization_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "deployment_managed_certificate_unique" ON "deployment" USING btree ("managed_certificate_id");--> statement-breakpoint
CREATE INDEX "deployment_org_idx" ON "deployment" USING btree ("organization_id","created_at");--> statement-breakpoint
CREATE INDEX "deployment_agent_idx" ON "deployment" USING btree ("agent_id");--> statement-breakpoint
CREATE INDEX "deployment_run_deployment_idx" ON "deployment_run" USING btree ("deployment_id","created_at");--> statement-breakpoint
ALTER TABLE "managed_certificate" ADD CONSTRAINT "managed_certificate_key_custody" CHECK ("managed_certificate"."key_custody" in ('owner', 'agent'));--> statement-breakpoint
ALTER TABLE "managed_certificate" ADD CONSTRAINT "managed_certificate_owner_has_csr" CHECK ("managed_certificate"."key_custody" <> 'owner' or "managed_certificate"."csr" is not null);