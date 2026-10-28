ALTER TABLE "adcs_ca" ADD COLUMN "discovery_failed_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "adcs_ca" ADD COLUMN "discovery_error" text;--> statement-breakpoint
ALTER TABLE "adcs_template" ADD COLUMN "reported" boolean DEFAULT true NOT NULL;--> statement-breakpoint
ALTER TABLE "adcs_template" ADD COLUMN "hidden" boolean DEFAULT false NOT NULL;