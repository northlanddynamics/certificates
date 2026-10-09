CREATE TABLE "managed_certificate_owner" (
	"id" bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY (sequence name "managed_certificate_owner_id_seq" INCREMENT BY 1 MINVALUE 1 MAXVALUE 9223372036854775807 START WITH 1 CACHE 1),
	"organization_id" text NOT NULL,
	"managed_certificate_id" uuid NOT NULL,
	"user_id" text,
	"team_id" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "managed_certificate_owner_user_xor_team" CHECK (("managed_certificate_owner"."user_id" is null) <> ("managed_certificate_owner"."team_id" is null))
);
--> statement-breakpoint
ALTER TABLE "managed_certificate" ADD COLUMN "archived_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "managed_certificate_owner" ADD CONSTRAINT "managed_certificate_owner_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "managed_certificate_owner" ADD CONSTRAINT "managed_certificate_owner_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "managed_certificate_owner" ADD CONSTRAINT "managed_certificate_owner_team_id_team_id_fk" FOREIGN KEY ("team_id") REFERENCES "public"."team"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "managed_certificate_owner" ADD CONSTRAINT "managed_certificate_owner_managed_certificate_id_organization_id_managed_certificate_id_organization_id_fk" FOREIGN KEY ("managed_certificate_id","organization_id") REFERENCES "public"."managed_certificate"("id","organization_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "managed_certificate_owner_user_unique" ON "managed_certificate_owner" USING btree ("managed_certificate_id","user_id") WHERE "managed_certificate_owner"."user_id" is not null;--> statement-breakpoint
CREATE UNIQUE INDEX "managed_certificate_owner_team_unique" ON "managed_certificate_owner" USING btree ("managed_certificate_id","team_id") WHERE "managed_certificate_owner"."team_id" is not null;--> statement-breakpoint
CREATE INDEX "managed_certificate_owner_user_idx" ON "managed_certificate_owner" USING btree ("organization_id","user_id");--> statement-breakpoint
CREATE INDEX "managed_certificate_owner_team_idx" ON "managed_certificate_owner" USING btree ("organization_id","team_id");