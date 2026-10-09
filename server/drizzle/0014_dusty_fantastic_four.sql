CREATE TABLE "name_change" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" text NOT NULL,
	"managed_certificate_id" uuid NOT NULL,
	"status" text NOT NULL,
	"names" text[] NOT NULL,
	"csr" text NOT NULL,
	"proposed_by_id" text NOT NULL,
	"proposed_by_email" text NOT NULL,
	"decided_by_id" text,
	"decided_by_email" text,
	"decided_at" timestamp with time zone,
	"decision_reason" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "name_change_status" CHECK ("name_change"."status" in ('pending', 'approved', 'rejected'))
);
--> statement-breakpoint
ALTER TABLE "name_change" ADD CONSTRAINT "name_change_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "name_change" ADD CONSTRAINT "name_change_managed_certificate_id_organization_id_managed_certificate_id_organization_id_fk" FOREIGN KEY ("managed_certificate_id","organization_id") REFERENCES "public"."managed_certificate"("id","organization_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "name_change_managed_certificate_idx" ON "name_change" USING btree ("managed_certificate_id","created_at");--> statement-breakpoint
CREATE INDEX "name_change_pending_idx" ON "name_change" USING btree ("organization_id") WHERE "name_change"."status" = 'pending';--> statement-breakpoint
CREATE UNIQUE INDEX "name_change_one_pending_per_managed_certificate" ON "name_change" USING btree ("managed_certificate_id") WHERE "name_change"."status" = 'pending';