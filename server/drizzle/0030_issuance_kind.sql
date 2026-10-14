ALTER TABLE "issuance" ADD COLUMN "kind" text;--> statement-breakpoint
-- What the Issuances that already exist were for. A first issue: none of the Managed Certificate's Certificates was issued
-- before it began. A Name Change: the change of names that had it begin was audited in the same change (at the same
-- moment), after a Certificate. Anything else is a Renewal, including a person trying a failed Name Change's Issuance
-- again, which is not told apart here.
UPDATE "issuance" i SET "kind" = CASE
  WHEN NOT EXISTS (
    SELECT 1 FROM "certificate" c WHERE c."managed_certificate_id" = i."managed_certificate_id" AND c."issued_at" < i."started_at"
  ) THEN 'first_issue'
  WHEN EXISTS (
    SELECT 1 FROM "audit_event" e
    WHERE e."organization_id" = i."organization_id" AND e."target_type" = 'managed_certificate' AND e."target_id" = i."managed_certificate_id"::text
      AND e."action" IN ('managed_certificate.names_changed', 'name_change.approved') AND e."occurred_at" = i."started_at"
  ) THEN 'name_change'
  ELSE 'renewal'
END;--> statement-breakpoint
ALTER TABLE "issuance" ALTER COLUMN "kind" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "issuance" ADD CONSTRAINT "issuance_kind" CHECK ("issuance"."kind" in ('first_issue', 'renewal', 'name_change'));
