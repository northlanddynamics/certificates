CREATE TABLE "certificate_revocation" (
	"certificate_id" uuid PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"reason" text NOT NULL,
	"revoked_by_id" text NOT NULL,
	"revoked_by_email" text NOT NULL,
	"revoked_at" timestamp with time zone NOT NULL,
	CONSTRAINT "certificate_revocation_reason" CHECK ("certificate_revocation"."reason" in ('unspecified', 'keyCompromise', 'superseded', 'cessationOfOperation'))
);
--> statement-breakpoint
ALTER TABLE "certificate_revocation" ADD CONSTRAINT "certificate_revocation_certificate_id_certificate_id_fk" FOREIGN KEY ("certificate_id") REFERENCES "public"."certificate"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "certificate_revocation" ADD CONSTRAINT "certificate_revocation_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "certificate_revocation_org_idx" ON "certificate_revocation" USING btree ("organization_id");