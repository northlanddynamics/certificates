import type { PermittedNames } from "@/lib/api";

/** A Private CA's permitted name rules in words, such as "app.example.com, or anything in internal.example". */
export function permittedNamesLabel({ exact, zones }: PermittedNames): string {
  if (exact.length === 0 && zones.length === 0) return "No names: it issues for nothing until an Organization Administrator sets them";
  const parts = [...(exact.length > 0 ? [exact.join(", ")] : []), ...(zones.length > 0 ? [`anything in ${zones.join(", ")}`] : [])];
  return parts.join(", or ");
}
