CREATE TABLE "renewal_info" (
	"certificate_id" uuid PRIMARY KEY NOT NULL,
	"organization_id" text NOT NULL,
	"window_start" timestamp with time zone,
	"window_end" timestamp with time zone,
	"checked_at" timestamp with time zone,
	"next_check_at" timestamp with time zone NOT NULL,
	CONSTRAINT "renewal_info_window" CHECK (("renewal_info"."window_start" is null) = ("renewal_info"."window_end" is null))
);
--> statement-breakpoint
ALTER TABLE "renewal_info" ADD CONSTRAINT "renewal_info_certificate_id_certificate_id_fk" FOREIGN KEY ("certificate_id") REFERENCES "public"."certificate"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "renewal_info" ADD CONSTRAINT "renewal_info_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE no action ON UPDATE no action;