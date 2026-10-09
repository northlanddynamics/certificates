ALTER TABLE "managed_certificate" ADD COLUMN "approval_status" text DEFAULT 'not_required' NOT NULL;--> statement-breakpoint
ALTER TABLE "managed_certificate" ADD COLUMN "proposed_by_id" text;--> statement-breakpoint
ALTER TABLE "managed_certificate" ADD COLUMN "proposed_by_email" text;--> statement-breakpoint
ALTER TABLE "managed_certificate" ADD COLUMN "decided_by_id" text;--> statement-breakpoint
ALTER TABLE "managed_certificate" ADD COLUMN "decided_by_email" text;--> statement-breakpoint
ALTER TABLE "managed_certificate" ADD COLUMN "decided_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "managed_certificate" ADD COLUMN "decision_reason" text;