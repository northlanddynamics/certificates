-- The plugin always sets these when it makes a key (auth.ts: 600 an hour); with two configurations the schema generator
-- can only show its own defaults, and CI wants the migrations to match what it generates.
ALTER TABLE "apikey" ALTER COLUMN "rate_limit_time_window" SET DEFAULT 86400000;--> statement-breakpoint
ALTER TABLE "apikey" ALTER COLUMN "rate_limit_max" SET DEFAULT 10;