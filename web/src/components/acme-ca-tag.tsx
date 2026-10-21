import { Badge } from "@/components/ui/badge";
import type { AcmeCaTag } from "@/lib/api";
import { ACME_CA_TAG_LABELS } from "@/lib/acme-cas";

/** An ACME CA's environment tag as a badge, production stronger than staging; nothing for an untagged one. */
export function AcmeCaTagBadge({ tag }: { tag: AcmeCaTag | null }) {
  if (!tag) return null;
  return <Badge variant={tag === "production" ? "default" : "secondary"}>{ACME_CA_TAG_LABELS[tag]}</Badge>;
}
