CREATE TABLE "revocation_request" (
	"id" uuid PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"certificate_id" uuid,
	"device_certificate_id" uuid,
	"reason" text NOT NULL,
	"requested_by_id" text,
	"requested_by_email" text,
	"requested_by" jsonb,
	"status" text NOT NULL,
	"handle" text NOT NULL,
	"deadline" timestamp with time zone NOT NULL,
	"failure_code" text,
	"failure_message" text,
	"requested_at" timestamp with time zone NOT NULL,
	"finished_at" timestamp with time zone,
	CONSTRAINT "revocation_request_certificate_unique" UNIQUE("certificate_id"),
	CONSTRAINT "revocation_request_device_certificate_unique" UNIQUE("device_certificate_id"),
	CONSTRAINT "revocation_request_of" CHECK (("revocation_request"."certificate_id" is null) <> ("revocation_request"."device_certificate_id" is null)),
	CONSTRAINT "revocation_request_status" CHECK ("revocation_request"."status" in ('pending', 'failed')),
	CONSTRAINT "revocation_request_failure" CHECK (("revocation_request"."status" = 'failed') = ("revocation_request"."failure_code" is not null and "revocation_request"."failure_message" is not null and "revocation_request"."finished_at" is not null)),
	CONSTRAINT "revocation_request_reason" CHECK ("revocation_request"."reason" in ('unspecified', 'keyCompromise', 'affiliationChanged', 'superseded', 'cessationOfOperation', 'privilegeWithdrawn'))
);
--> statement-breakpoint
ALTER TABLE "revocation_request" ADD CONSTRAINT "revocation_request_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "revocation_request" ADD CONSTRAINT "revocation_request_certificate_id_certificate_id_fk" FOREIGN KEY ("certificate_id") REFERENCES "public"."certificate"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "revocation_request" ADD CONSTRAINT "revocation_request_device_certificate_id_device_certificate_id_fk" FOREIGN KEY ("device_certificate_id") REFERENCES "public"."device_certificate"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "revocation_request_deadline_idx" ON "revocation_request" USING btree ("deadline") WHERE "revocation_request"."status" = 'pending';