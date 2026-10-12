ALTER TABLE "dns_provider" ADD CONSTRAINT "dns_provider_id_organization_unique" UNIQUE("id","organization_id");--> statement-breakpoint
CREATE TABLE "dcv_rule" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" text NOT NULL,
	"scope" text NOT NULL,
	"domain" text NOT NULL,
	"method" text NOT NULL,
	"dns_provider_id" uuid,
	"validation_zone_id" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "dcv_rule_organization_scope_domain_unique" UNIQUE("organization_id","scope","domain"),
	CONSTRAINT "dcv_rule_scope" CHECK ("dcv_rule"."scope" in ('name', 'zone')),
	CONSTRAINT "dcv_rule_method" CHECK (("dcv_rule"."method" = 'direct' and "dcv_rule"."validation_zone_id" is null) or ("dcv_rule"."method" = 'delegated' and "dcv_rule"."validation_zone_id" is not null and "dcv_rule"."dns_provider_id" is null))
);
--> statement-breakpoint
CREATE TABLE "validation_zone" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" text NOT NULL,
	"name" text NOT NULL,
	"dns_provider_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "validation_zone_organization_name_unique" UNIQUE("organization_id","name"),
	CONSTRAINT "validation_zone_id_organization_unique" UNIQUE("id","organization_id")
);
--> statement-breakpoint
ALTER TABLE "dcv_rule" ADD CONSTRAINT "dcv_rule_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dcv_rule" ADD CONSTRAINT "dcv_rule_dns_provider_id_organization_id_dns_provider_id_organization_id_fk" FOREIGN KEY ("dns_provider_id","organization_id") REFERENCES "public"."dns_provider"("id","organization_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dcv_rule" ADD CONSTRAINT "dcv_rule_validation_zone_id_organization_id_validation_zone_id_organization_id_fk" FOREIGN KEY ("validation_zone_id","organization_id") REFERENCES "public"."validation_zone"("id","organization_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "validation_zone" ADD CONSTRAINT "validation_zone_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "validation_zone" ADD CONSTRAINT "validation_zone_dns_provider_id_organization_id_dns_provider_id_organization_id_fk" FOREIGN KEY ("dns_provider_id","organization_id") REFERENCES "public"."dns_provider"("id","organization_id") ON DELETE no action ON UPDATE no action;
