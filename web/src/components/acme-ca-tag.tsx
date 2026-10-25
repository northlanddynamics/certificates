import { Badge } from "@/components/ui/badge";
import type { AcmeCaTag } from "@/lib/api";
import { ACME_CA_TAG_LABELS } from "@/lib/acme-cas";
import { cn } from "@/lib/utils";

/**
 * An ACME CA's environment tag, styled apart from any status: an outline with a dot, filled for production and hollow
 * for staging; nothing for an untagged one.
 */
export function AcmeCaTagBadge({ tag }: { tag: AcmeCaTag | null }) {
  if (!tag) return null;
  return (
    <Badge variant="outline">
      <span aria-hidden className={cn("size-1.5 rounded-full border border-current", tag === "production" && "bg-current")} />
      {ACME_CA_TAG_LABELS[tag]}
    </Badge>
  );
}
