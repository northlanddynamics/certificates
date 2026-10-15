-- A Private CA's permitted name rules (permitted-names.ts). A Private CA made before them has none, and issues for
-- nothing until an Organization Administrator sets some.
ALTER TABLE "private_ca" ADD COLUMN "permitted_exact_names" text[] DEFAULT '{}' NOT NULL;--> statement-breakpoint
ALTER TABLE "private_ca" ADD COLUMN "permitted_zones" text[] DEFAULT '{}' NOT NULL;