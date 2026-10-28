ALTER TABLE "adcs_request" DROP CONSTRAINT "adcs_request_status";--> statement-breakpoint
DROP INDEX "adcs_request_open_idx";--> statement-breakpoint
ALTER TABLE "adcs_request" ADD COLUMN "checks" integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE "adcs_request" ADD COLUMN "next_check_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "adcs_request" ADD COLUMN "check_given_at" timestamp with time zone;--> statement-breakpoint
CREATE INDEX "adcs_request_open_idx" ON "adcs_request" USING btree ("status") WHERE "adcs_request"."status" in ('waiting', 'submitted', 'pending');--> statement-breakpoint
ALTER TABLE "adcs_request" ADD CONSTRAINT "adcs_request_pending" CHECK ("adcs_request"."status" <> 'pending' or ("adcs_request"."adcs_request_id" is not null and "adcs_request"."submitted_at" is not null and "adcs_request"."next_check_at" is not null and ("adcs_request"."work_item_id" is null or ("adcs_request"."agent_id" is not null and "adcs_request"."check_given_at" is not null))));--> statement-breakpoint
ALTER TABLE "adcs_request" ADD CONSTRAINT "adcs_request_status" CHECK ("adcs_request"."status" in ('waiting', 'submitted', 'pending', 'issued', 'failed'));