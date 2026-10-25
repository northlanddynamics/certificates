ALTER TABLE "certificate_profile" ADD COLUMN "allowed_exact_names" text[] DEFAULT '{}' NOT NULL;--> statement-breakpoint
ALTER TABLE "certificate_profile" ADD COLUMN "allowed_zones" text[] DEFAULT '{}' NOT NULL;--> statement-breakpoint
ALTER TABLE "certificate_profile" ADD COLUMN "max_names" integer;--> statement-breakpoint
ALTER TABLE "certificate_profile" ADD COLUMN "wildcards_allowed" boolean DEFAULT true NOT NULL;--> statement-breakpoint
ALTER TABLE "certificate_profile" ADD CONSTRAINT "certificate_profile_max_names" CHECK ("certificate_profile"."max_names" is null or "certificate_profile"."max_names" >= 1);