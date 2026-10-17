ALTER TABLE "enrollment_profile" ADD COLUMN "shared_challenge_id" uuid;--> statement-breakpoint
ALTER TABLE "enrollment_profile" ADD COLUMN "shared_challenge_hash" text;--> statement-breakpoint
ALTER TABLE "enrollment_profile" ADD CONSTRAINT "enrollment_profile_shared_challenge" CHECK (("enrollment_profile"."shared_challenge_id" is null) = ("enrollment_profile"."shared_challenge_hash" is null));