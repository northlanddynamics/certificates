CREATE TABLE "dns_provider_relay_agent" (
	"organization_id" text NOT NULL,
	"dns_provider_id" uuid NOT NULL,
	"agent_id" uuid NOT NULL,
	CONSTRAINT "dns_provider_relay_agent_dns_provider_id_agent_id_pk" PRIMARY KEY("dns_provider_id","agent_id")
);
--> statement-breakpoint
CREATE TABLE "work_item" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" text NOT NULL,
	"agent_id" uuid NOT NULL,
	"type" text NOT NULL,
	"payload" jsonb NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"created_at" timestamp with time zone NOT NULL,
	"delivered_at" timestamp with time zone,
	"finished_at" timestamp with time zone,
	"result" jsonb,
	CONSTRAINT "work_item_status" CHECK ("work_item"."status" in ('pending', 'delivered', 'succeeded', 'failed', 'expired'))
);
--> statement-breakpoint
ALTER TABLE "dns_provider_relay_agent" ADD CONSTRAINT "dns_provider_relay_agent_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dns_provider_relay_agent" ADD CONSTRAINT "dns_provider_relay_agent_dns_provider_id_organization_id_dns_provider_id_organization_id_fk" FOREIGN KEY ("dns_provider_id","organization_id") REFERENCES "public"."dns_provider"("id","organization_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dns_provider_relay_agent" ADD CONSTRAINT "dns_provider_relay_agent_agent_id_organization_id_agent_id_organization_id_fk" FOREIGN KEY ("agent_id","organization_id") REFERENCES "public"."agent"("id","organization_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "work_item" ADD CONSTRAINT "work_item_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "work_item" ADD CONSTRAINT "work_item_agent_id_organization_id_agent_id_organization_id_fk" FOREIGN KEY ("agent_id","organization_id") REFERENCES "public"."agent"("id","organization_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "dns_provider_relay_agent_agent_idx" ON "dns_provider_relay_agent" USING btree ("agent_id");--> statement-breakpoint
CREATE INDEX "work_item_agent_idx" ON "work_item" USING btree ("agent_id","status");