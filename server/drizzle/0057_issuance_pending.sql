ALTER TABLE "issuance" ADD COLUMN "pending_handle" text;--> statement-breakpoint
ALTER TABLE "issuance" ADD COLUMN "pending_until" timestamp with time zone;--> statement-breakpoint
CREATE INDEX "issuance_pending_until_idx" ON "issuance" USING btree ("pending_until") WHERE "issuance"."status" = 'running' and "issuance"."pending_until" is not null;--> statement-breakpoint
ALTER TABLE "issuance" ADD CONSTRAINT "issuance_pending" CHECK (("issuance"."pending_handle" is null) = ("issuance"."pending_until" is null));