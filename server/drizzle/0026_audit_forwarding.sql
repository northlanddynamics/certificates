CREATE TABLE "audit_delivery" (
	"forwarder_id" uuid NOT NULL,
	"organization_id" text NOT NULL,
	"audit_event_id" bigint NOT NULL,
	CONSTRAINT "audit_delivery_forwarder_id_audit_event_id_pk" PRIMARY KEY("forwarder_id","audit_event_id")
);
--> statement-breakpoint
CREATE TABLE "audit_forwarder" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" text NOT NULL,
	"name" text NOT NULL,
	"kind" text NOT NULL,
	"secret_id" uuid,
	"host" text NOT NULL,
	"port" integer,
	"created_at" timestamp with time zone NOT NULL,
	"failures" integer DEFAULT 0 NOT NULL,
	"next_attempt_at" timestamp with time zone NOT NULL,
	"last_delivered_at" timestamp with time zone,
	"last_error" text,
	CONSTRAINT "audit_forwarder_kind" CHECK ("audit_forwarder"."kind" in ('webhook', 'syslog')),
	CONSTRAINT "audit_forwarder_target" CHECK (("audit_forwarder"."kind" = 'webhook' and "audit_forwarder"."secret_id" is not null) or ("audit_forwarder"."kind" = 'syslog' and "audit_forwarder"."port" is not null))
);
--> statement-breakpoint
ALTER TABLE "audit_delivery" ADD CONSTRAINT "audit_delivery_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_delivery" ADD CONSTRAINT "audit_delivery_audit_event_id_audit_event_id_fk" FOREIGN KEY ("audit_event_id") REFERENCES "public"."audit_event"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_forwarder" ADD CONSTRAINT "audit_forwarder_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_forwarder" ADD CONSTRAINT "audit_forwarder_secret_id_organization_id_secret_id_organization_id_fk" FOREIGN KEY ("secret_id","organization_id") REFERENCES "public"."secret"("id","organization_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "audit_forwarder_due_idx" ON "audit_forwarder" USING btree ("next_attempt_at");--> statement-breakpoint
CREATE UNIQUE INDEX "audit_forwarder_name_unique" ON "audit_forwarder" USING btree ("organization_id",lower("name"));--> statement-breakpoint
CREATE INDEX "audit_event_action_idx" ON "audit_event" USING btree ("organization_id","action","id");--> statement-breakpoint
CREATE INDEX "audit_event_target_idx" ON "audit_event" USING btree ("organization_id","target_type","target_id","id");--> statement-breakpoint
CREATE INDEX "audit_event_actor_email_idx" ON "audit_event" USING btree ("organization_id",lower("actor_email"),"id");--> statement-breakpoint
CREATE INDEX "audit_event_actor_id_idx" ON "audit_event" USING btree ("organization_id","actor_id","id");--> statement-breakpoint
CREATE INDEX "audit_event_occurred_at_idx" ON "audit_event" USING btree ("organization_id","occurred_at");