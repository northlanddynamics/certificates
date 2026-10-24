// The audit log's search as its address keeps it, and the filters the API is given for it. Pure and free of the app's
// imports, so the server's tests can run it.

/** The time ranges offered: a quick pick back from now, or one chosen. */
export const AUDIT_RANGES = ["24h", "7d", "30d", "custom"] as const;
export type AuditRange = (typeof AUDIT_RANGES)[number];

/** The audit log's search in the address: part of an actor's email or an action, target types, and a time range. */
export interface AuditSearch {
  q?: string;
  /** Target types, any of. */
  types?: string[];
  range?: AuditRange;
  /** For a custom range: ISO times, from inclusive, to exclusive; either may be left open. */
  from?: string;
  to?: string;
}

const HOURS: Record<Exclude<AuditRange, "custom">, number> = { "24h": 24, "7d": 7 * 24, "30d": 30 * 24 };
const isTime = (value: unknown): value is string => typeof value === "string" && !Number.isNaN(Date.parse(value));

/** What of an address's search is an audit search; anything else, or malformed, is dropped. */
export function auditSearchOf(raw: Record<string, unknown>): AuditSearch {
  const search: AuditSearch = {};
  if (typeof raw.q === "string" && raw.q.trim() !== "") search.q = raw.q.trim();
  const types = (Array.isArray(raw.types) ? raw.types : typeof raw.types === "string" ? raw.types.split(",") : []).filter((t): t is string => typeof t === "string" && /^[a-z_]+$/.test(t));
  if (types.length > 0) search.types = types;
  if (AUDIT_RANGES.includes(raw.range as AuditRange)) search.range = raw.range as AuditRange;
  if (search.range === "custom") {
    if (isTime(raw.from)) search.from = raw.from;
    if (isTime(raw.to)) search.to = raw.to;
  }
  return search;
}

/** The API's filters for `search`, a quick range counted back from `now`. */
export function auditFiltersOf(search: AuditSearch, now: Date): { q?: string; targetType?: string; from?: string; to?: string } {
  const { q, types, range } = search;
  const from = range === "custom" ? search.from : range ? new Date(now.getTime() - HOURS[range] * 3_600_000).toISOString() : undefined;
  const to = range === "custom" ? search.to : undefined;
  return { ...(q && { q }), ...(types?.length && { targetType: types.join(",") }), ...(from && { from }), ...(to && { to }) };
}

/** A target type as people read it: `managed_certificate` as "Managed certificate". */
export const targetTypeLabel = (type: string) => {
  const words = type.replace(/_/g, " ");
  return words.charAt(0).toUpperCase() + words.slice(1);
};
