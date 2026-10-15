ALTER TABLE "certificate_revocation" DROP CONSTRAINT "certificate_revocation_reason";--> statement-breakpoint
ALTER TABLE "issuing_ca" ADD COLUMN "crl_number" bigint;--> statement-breakpoint
ALTER TABLE "issuing_ca" ADD COLUMN "crl_this_update" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "issuing_ca" ADD COLUMN "crl_next_update" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "issuing_ca" ADD COLUMN "crl_der" "bytea";--> statement-breakpoint
ALTER TABLE "issuing_ca" ADD COLUMN "crl_failing_since" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "private_ca" ADD COLUMN "crl_number" bigint;--> statement-breakpoint
ALTER TABLE "private_ca" ADD COLUMN "crl_this_update" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "private_ca" ADD COLUMN "crl_next_update" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "private_ca" ADD COLUMN "crl_der" "bytea";--> statement-breakpoint
ALTER TABLE "private_ca" ADD COLUMN "crl_failing_since" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "certificate_revocation" ADD CONSTRAINT "certificate_revocation_reason" CHECK ("certificate_revocation"."reason" in ('unspecified', 'keyCompromise', 'affiliationChanged', 'superseded', 'cessationOfOperation', 'privilegeWithdrawn'));