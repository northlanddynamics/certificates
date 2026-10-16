CREATE TABLE "enrollment_validator_feed" (
	"organization_id" text NOT NULL,
	"validator_kind" text NOT NULL,
	"source" text NOT NULL,
	"last_pulled_at" timestamp with time zone,
	"next_pull_at" timestamp with time zone NOT NULL,
	CONSTRAINT "enrollment_validator_feed_organization_id_validator_kind_source_pk" PRIMARY KEY("organization_id","validator_kind","source")
);
--> statement-breakpoint
CREATE TABLE "enrollment_validator_message" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" text NOT NULL,
	"enrollment_profile_id" uuid NOT NULL,
	"type" text NOT NULL,
	"payload" jsonb NOT NULL,
	"status" text DEFAULT 'queued' NOT NULL,
	"attempts" integer DEFAULT 0 NOT NULL,
	"next_attempt_at" timestamp with time zone NOT NULL,
	"last_error" text,
	"created_at" timestamp with time zone NOT NULL,
	"sent_at" timestamp with time zone,
	CONSTRAINT "enrollment_validator_message_type" CHECK ("enrollment_validator_message"."type" in ('issued', 'failed', 'revocations')),
	CONSTRAINT "enrollment_validator_message_status" CHECK ("enrollment_validator_message"."status" in ('queued', 'sent', 'failed'))
);
--> statement-breakpoint
CREATE TABLE "enrollment_validator_revocation_request" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" text NOT NULL,
	"validator_kind" text NOT NULL,
	"source" text NOT NULL,
	"ref" text NOT NULL,
	"serial" text NOT NULL,
	"issuer" text,
	"reason" text NOT NULL,
	"attempts" integer DEFAULT 0 NOT NULL,
	"pulled_at" timestamp with time zone NOT NULL,
	"position" integer NOT NULL,
	CONSTRAINT "enrollment_validator_revocation_request_reason" CHECK ("enrollment_validator_revocation_request"."reason" in ('unspecified', 'keyCompromise', 'affiliationChanged', 'superseded', 'cessationOfOperation', 'privilegeWithdrawn'))
);
--> statement-breakpoint
ALTER TABLE "device_certificate" ADD COLUMN "revoked_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "device_certificate" ADD COLUMN "revocation_reason" text;--> statement-breakpoint
ALTER TABLE "enrollment_profile" ADD COLUMN "validator_settings" jsonb DEFAULT '{}'::jsonb NOT NULL;--> statement-breakpoint
ALTER TABLE "enrollment_profile" ADD COLUMN "validator_secret_id" uuid;--> statement-breakpoint
ALTER TABLE "enrollment_profile" ADD COLUMN "name_rules" jsonb;--> statement-breakpoint
ALTER TABLE "enrollment_validator_feed" ADD CONSTRAINT "enrollment_validator_feed_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "enrollment_validator_message" ADD CONSTRAINT "enrollment_validator_message_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "enrollment_validator_message" ADD CONSTRAINT "enrollment_validator_message_enrollment_profile_id_organization_id_enrollment_profile_id_organization_id_fk" FOREIGN KEY ("enrollment_profile_id","organization_id") REFERENCES "public"."enrollment_profile"("id","organization_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "enrollment_validator_revocation_request" ADD CONSTRAINT "enrollment_validator_revocation_request_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "enrollment_validator_message_queued_idx" ON "enrollment_validator_message" USING btree ("next_attempt_at") WHERE "enrollment_validator_message"."status" = 'queued';--> statement-breakpoint
CREATE INDEX "enrollment_validator_revocation_request_feed_idx" ON "enrollment_validator_revocation_request" USING btree ("organization_id","validator_kind","source","pulled_at","position");--> statement-breakpoint
ALTER TABLE "enrollment_profile" ADD CONSTRAINT "enrollment_profile_validator_secret_id_organization_id_secret_id_organization_id_fk" FOREIGN KEY ("validator_secret_id","organization_id") REFERENCES "public"."secret"("id","organization_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "device_certificate_serial_idx" ON "device_certificate" USING btree ("organization_id","serial");--> statement-breakpoint
CREATE INDEX "device_certificate_revoked_idx" ON "device_certificate" USING btree ("issuing_ca_id") WHERE "device_certificate"."revoked_at" is not null;--> statement-breakpoint
ALTER TABLE "device_certificate" ADD CONSTRAINT "device_certificate_revocation" CHECK (("device_certificate"."revoked_at" is null) = ("device_certificate"."revocation_reason" is null));--> statement-breakpoint
ALTER TABLE "device_certificate" ADD CONSTRAINT "device_certificate_revocation_reason" CHECK ("device_certificate"."revocation_reason" in ('unspecified', 'keyCompromise', 'affiliationChanged', 'superseded', 'cessationOfOperation', 'privilegeWithdrawn'));