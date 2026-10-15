import type { PermittedNames, PrivateCaValidity } from "@/lib/api";
// The server's own limits, from a module that imports nothing, so what the forms offer is what the API accepts.
import { DEFAULT_VALIDITY_DAYS, MAX_VALIDITY_DAYS } from "../../../server/src/private-ca-kinds";

export { DEFAULT_VALIDITY_DAYS, MAX_VALIDITY_DAYS };

/** A Private CA's permitted name rules in words, such as "app.example.com, or anything in internal.example". */
export function permittedNamesLabel({ exact, zones }: PermittedNames): string {
  if (exact.length === 0 && zones.length === 0) return "No names: it issues for nothing until an Organization Administrator sets them";
  const parts = [...(exact.length > 0 ? [exact.join(", ")] : []), ...(zones.length > 0 ? [`anything in ${zones.join(", ")}`] : [])];
  return parts.join(", or ");
}

/** A number of days in words, such as "1 day" or "397 days". */
export const daysLabel = (days: number) => `${days} ${days === 1 ? "day" : "days"}`;

/** A Private CA's validity limits in words, such as "90 days by default, at most 397 days". */
export const validityLabel = ({ maximumDays, defaultDays }: PrivateCaValidity) =>
  defaultDays === maximumDays ? `${daysLabel(maximumDays)}, at most` : `${daysLabel(defaultDays)} by default, at most ${daysLabel(maximumDays)}`;

/** Whether `text` is a whole number of days from 1 to `max`. */
export const isValidityDays = (text: string, max = MAX_VALIDITY_DAYS) => /^\d+$/.test(text.trim()) && Number(text) >= 1 && Number(text) <= max;

/** A Managed Certificate's validity in words: its days, or its Private CA's default. */
export const chosenValidityLabel = (validityDays: number | null) => (validityDays === null ? "the Private CA's default" : daysLabel(validityDays));
