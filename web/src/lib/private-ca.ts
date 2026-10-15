import type { PermittedNames, PrivateCaValidity } from "@/lib/api";
// The server's own limits, from a module that imports nothing, so what the forms offer is what the API accepts.
import { DEFAULT_VALIDITY_DAYS, MAX_VALIDITY_DAYS } from "../../../server/src/private-ca-kinds";

export { DEFAULT_VALIDITY_DAYS, MAX_VALIDITY_DAYS };

/** An Issuing CA's permitted name rules in words, such as "app.example.com, or anything in internal.example", or "Not set". */
export function permittedNamesLabel({ exact, zones }: PermittedNames): string {
  if (exact.length === 0 && zones.length === 0) return "Not set";
  const parts = [...(exact.length > 0 ? [exact.join(", ")] : []), ...(zones.length > 0 ? [`anything in ${zones.join(", ")}`] : [])];
  return parts.join(", or ");
}

/** The common name in a distinguished name, such as "Acme Devices" in "CN=Acme Devices, O=Acme"; the whole of it when it has none. */
export const commonNameOf = (subject: string) => /(?:^|,\s*)CN=([^,]+)/i.exec(subject)?.[1]?.trim() ?? subject;

/** An Issuing CA as it is named to someone choosing it: its common name, and its Private CA's name. */
export const issuingCaTitle = (privateCaName: string, issuingCaSubject: string) => `${commonNameOf(issuingCaSubject)} (Private CA ${privateCaName})`;

/** What the Issuing CA, named `name`, issues for, as a sentence for a field that takes names. */
export const permitsOnlyLabel = (ca: { name: string; permittedNames: PermittedNames }) =>
  ca.permittedNames.exact.length + ca.permittedNames.zones.length === 0
    ? `${ca.name} has no permitted names set, so every name is refused.`
    : `${ca.name} permits only ${permittedNamesLabel(ca.permittedNames)}; other names are refused.`;

/** The root's subject for an Issuing CA's `subject`: the same, with " Root" after the common name. */
export const rootSubjectOf = (subject: string) => subject.replace(/(^|,\s*)(CN=)([^,]+)/i, (_, start: string, cn: string, value: string) => `${start}${cn}${value.trim()} Root`);

/** A number of days in words, such as "1 day" or "397 days". */
export const daysLabel = (days: number) => `${days} ${days === 1 ? "day" : "days"}`;

/** An Issuing CA's validity limits in words, such as "90 days by default, at most 397 days". */
export const validityLabel = ({ maximumDays, defaultDays }: PrivateCaValidity) =>
  defaultDays === maximumDays ? `${daysLabel(maximumDays)}, at most` : `${daysLabel(defaultDays)} by default, at most ${daysLabel(maximumDays)}`;

/** Whether `text` is a whole number of days from 1 to `max`. */
export const isValidityDays = (text: string, max = MAX_VALIDITY_DAYS) => /^\d+$/.test(text.trim()) && Number(text) >= 1 && Number(text) <= max;

/** A Managed Certificate's validity in words: its days, or its Issuing CA's default. */
export const chosenValidityLabel = (validityDays: number | null) => (validityDays === null ? "the Issuing CA's default" : daysLabel(validityDays));
