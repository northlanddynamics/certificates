CREATE TABLE "scep_transaction" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" text NOT NULL,
	"enrollment_profile_id" uuid NOT NULL,
	"transaction_id" text NOT NULL,
	"claimed_at" timestamp with time zone NOT NULL,
	"device_certificate_id" uuid,
	"refusal" text,
	CONSTRAINT "scep_transaction_profile_transaction_unique" UNIQUE("enrollment_profile_id","transaction_id"),
	CONSTRAINT "scep_transaction_answer" CHECK ("scep_transaction"."device_certificate_id" is null or "scep_transaction"."refusal" is null)
);
--> statement-breakpoint
ALTER TABLE "scep_transaction" ADD CONSTRAINT "scep_transaction_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scep_transaction" ADD CONSTRAINT "scep_transaction_device_certificate_id_device_certificate_id_fk" FOREIGN KEY ("device_certificate_id") REFERENCES "public"."device_certificate"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scep_transaction" ADD CONSTRAINT "scep_transaction_enrollment_profile_id_organization_id_enrollment_profile_id_organization_id_fk" FOREIGN KEY ("enrollment_profile_id","organization_id") REFERENCES "public"."enrollment_profile"("id","organization_id") ON DELETE no action ON UPDATE no action;