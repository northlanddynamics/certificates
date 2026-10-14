CREATE TABLE "managed_certificate_subscriber" (
	"id" bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY (sequence name "managed_certificate_subscriber_id_seq" INCREMENT BY 1 MINVALUE 1 MAXVALUE 9223372036854775807 START WITH 1 CACHE 1),
	"organization_id" text NOT NULL,
	"managed_certificate_id" uuid NOT NULL,
	"user_id" text,
	"team_id" text,
	"channel_id" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "managed_certificate_subscriber_one_of" CHECK (num_nonnulls("managed_certificate_subscriber"."user_id", "managed_certificate_subscriber"."team_id", "managed_certificate_subscriber"."channel_id") = 1)
);
--> statement-breakpoint
CREATE TABLE "notice" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" text NOT NULL,
	"event" text NOT NULL,
	"email" text,
	"channel_id" uuid,
	"subject" text NOT NULL,
	"text" text NOT NULL,
	"payload" jsonb NOT NULL,
	"status" text DEFAULT 'queued' NOT NULL,
	"attempts" integer DEFAULT 0 NOT NULL,
	"next_attempt_at" timestamp with time zone NOT NULL,
	"last_error" text,
	"created_at" timestamp with time zone NOT NULL,
	"sent_at" timestamp with time zone,
	CONSTRAINT "notice_status" CHECK ("notice"."status" in ('queued', 'sent', 'failed')),
	CONSTRAINT "notice_recipient" CHECK ("notice"."email" is not null or "notice"."channel_id" is not null)
);
--> statement-breakpoint
CREATE TABLE "noticed_condition" (
	"organization_id" text NOT NULL,
	"key" text NOT NULL,
	"noticed_at" timestamp with time zone NOT NULL,
	CONSTRAINT "noticed_condition_organization_id_key_pk" PRIMARY KEY("organization_id","key")
);
--> statement-breakpoint
CREATE TABLE "notification_channel" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" text NOT NULL,
	"name" text NOT NULL,
	"kind" text NOT NULL,
	"email" text,
	"secret_id" uuid,
	"webhook_host" text,
	"created_at" timestamp with time zone NOT NULL,
	CONSTRAINT "notification_channel_id_organization_unique" UNIQUE("id","organization_id"),
	CONSTRAINT "notification_channel_kind" CHECK ("notification_channel"."kind" in ('email', 'webhook')),
	CONSTRAINT "notification_channel_target" CHECK (("notification_channel"."kind" = 'email' and "notification_channel"."email" is not null) or ("notification_channel"."kind" = 'webhook' and "notification_channel"."secret_id" is not null))
);
--> statement-breakpoint
ALTER TABLE "managed_certificate_subscriber" ADD CONSTRAINT "managed_certificate_subscriber_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "managed_certificate_subscriber" ADD CONSTRAINT "managed_certificate_subscriber_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "managed_certificate_subscriber" ADD CONSTRAINT "managed_certificate_subscriber_team_id_team_id_fk" FOREIGN KEY ("team_id") REFERENCES "public"."team"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "managed_certificate_subscriber" ADD CONSTRAINT "managed_certificate_subscriber_managed_certificate_id_organization_id_managed_certificate_id_organization_id_fk" FOREIGN KEY ("managed_certificate_id","organization_id") REFERENCES "public"."managed_certificate"("id","organization_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "managed_certificate_subscriber" ADD CONSTRAINT "managed_certificate_subscriber_channel_id_organization_id_notification_channel_id_organization_id_fk" FOREIGN KEY ("channel_id","organization_id") REFERENCES "public"."notification_channel"("id","organization_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "notice" ADD CONSTRAINT "notice_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "notice" ADD CONSTRAINT "notice_channel_id_organization_id_notification_channel_id_organization_id_fk" FOREIGN KEY ("channel_id","organization_id") REFERENCES "public"."notification_channel"("id","organization_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "noticed_condition" ADD CONSTRAINT "noticed_condition_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "notification_channel" ADD CONSTRAINT "notification_channel_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "notification_channel" ADD CONSTRAINT "notification_channel_secret_id_organization_id_secret_id_organization_id_fk" FOREIGN KEY ("secret_id","organization_id") REFERENCES "public"."secret"("id","organization_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "managed_certificate_subscriber_user_unique" ON "managed_certificate_subscriber" USING btree ("managed_certificate_id","user_id") WHERE "managed_certificate_subscriber"."user_id" is not null;--> statement-breakpoint
CREATE UNIQUE INDEX "managed_certificate_subscriber_team_unique" ON "managed_certificate_subscriber" USING btree ("managed_certificate_id","team_id") WHERE "managed_certificate_subscriber"."team_id" is not null;--> statement-breakpoint
CREATE UNIQUE INDEX "managed_certificate_subscriber_channel_unique" ON "managed_certificate_subscriber" USING btree ("managed_certificate_id","channel_id") WHERE "managed_certificate_subscriber"."channel_id" is not null;--> statement-breakpoint
CREATE INDEX "managed_certificate_subscriber_user_idx" ON "managed_certificate_subscriber" USING btree ("organization_id","user_id");--> statement-breakpoint
CREATE INDEX "managed_certificate_subscriber_team_idx" ON "managed_certificate_subscriber" USING btree ("organization_id","team_id");--> statement-breakpoint
CREATE INDEX "managed_certificate_subscriber_channel_idx" ON "managed_certificate_subscriber" USING btree ("channel_id");--> statement-breakpoint
CREATE INDEX "notice_queued_idx" ON "notice" USING btree ("next_attempt_at") WHERE "notice"."status" = 'queued';--> statement-breakpoint
CREATE INDEX "notification_channel_org_idx" ON "notification_channel" USING btree ("organization_id","created_at");--> statement-breakpoint
CREATE UNIQUE INDEX "notification_channel_name_unique" ON "notification_channel" USING btree ("organization_id",lower("name"));