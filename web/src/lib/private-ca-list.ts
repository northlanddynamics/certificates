// What the Private CAs page says of each of the Organization's own CAs, of either kind: those the platform runs, with
// their keys in its KMS, and its ADCS CAs, reached through Agents. Pure and free of the app's imports, so the server's
// tests can run it.
import type { AdcsCa, IssuingCa, PrivateCa } from "./api";
import { commonNameOf, daysLabel, permittedNamesLabel } from "./private-ca";

const DAY_MS = 24 * 60 * 60 * 1000;

/** Which of the two kinds a CA on the page is: run by the platform, or an ADCS CA. */
export type CaKind = "platform" | "adcs";
export const CA_KIND_LABELS: Record<CaKind, string> = { platform: "Platform", adcs: "AD CS" };

/** How urgent something on the page is: `bad` stops issuance, `warn` needs doing soon or weakens a safeguard. */
export type Tone = "bad" | "warn";

/** Something about one CA that needs an Organization Administrator, as the page's "Needs attention" lists it. */
export interface Attention {
  kind: CaKind;
  caId: string;
  caName: string;
  tone: Tone;
  title: string;
  detail: string;
}

/**
 * Where an active Issuing CA stands with its end: none while it outlasts its maximum validity; else the days left, and
 * whether it has ended. Short of its end, what it issues is cut short, so it is time to roll over.
 */
export function rolloverOf(issuing: Pick<IssuingCa, "status" | "notAfter" | "validity">, now: Date): { daysLeft: number; ended: boolean } | null {
  if (issuing.status !== "active" || !issuing.notAfter) return null;
  const daysLeft = Math.floor((new Date(issuing.notAfter).getTime() - now.getTime()) / DAY_MS);
  if (daysLeft >= issuing.validity.maximumDays) return null;
  return { daysLeft, ended: daysLeft <= 0 };
}

/** What needs attention on a CA the platform runs, worst first: an Issuing CA that has ended, one due to roll over, one awaiting its signature. */
export function platformAttention(ca: PrivateCa, now: Date): Attention[] {
  // A revoked root's Issuing CAs issue nothing, for good: there is nothing left to do.
  if (ca.status === "revoked") return [];
  const of = (tone: Tone, title: string, detail: string): Attention => ({ kind: "platform", caId: ca.id, caName: ca.name, tone, title, detail });
  const found: Attention[] = [];
  for (const issuing of ca.issuingCas) {
    const name = commonNameOf(issuing.subject);
    const rollover = rolloverOf(issuing, now);
    if (rollover?.ended) found.push(of("bad", "Issuing CA ended", `${name} has ended and issues nothing. Repoint its Managed Certificates to another Issuing CA.`));
    else if (rollover)
      found.push(
        of(
          "warn",
          "Rollover due",
          `${name} ends in ${daysLabel(rollover.daysLeft)}, sooner than its maximum validity, so what it issues now is cut short. Add another Issuing CA under the root and repoint its Managed Certificates.`,
        ),
      );
    if (issuing.status === "awaiting_signature") found.push(of("warn", "Awaiting signature", `${name} issues nothing until you upload what your root signed for its CSR.`));
  }
  return worstFirst(found);
}

/** What needs attention on an ADCS CA, worst first: a failed discovery, and no Permitted Name Rules. */
export function adcsAttention(ca: AdcsCa): Attention[] {
  const of = (tone: Tone, title: string, detail: string): Attention => ({ kind: "adcs", caId: ca.id, caName: ca.name, tone, title, detail });
  return [
    ...(ca.discoveryFailure ? [of("bad", "Discovery failed", `${ca.discoveryFailure.error} Its chain and templates are from the last discovery that worked.`)] : []),
    ...(ca.permittedNames ? [] : [of("warn", "No Permitted Name Rules", "Approval alone decides which names ADCS is asked for.")]),
  ];
}

const worstFirst = (items: Attention[]) => [...items.filter((a) => a.tone === "bad"), ...items.filter((a) => a.tone === "warn")];

/** A CA's health in a few words: what its worst attention is, else healthy, or revoked for a revoked root. */
export type Health = { tone: Tone | "ok" | "neutral"; label: string };
export function healthOf(attention: Attention[], revoked = false): Health {
  if (revoked) return { tone: "neutral", label: "Revoked" };
  const worst = attention[0];
  return worst ? { tone: worst.tone, label: worst.title } : { tone: "ok", label: "Healthy" };
}

/** One CA as a row of the page's table, whichever its kind. */
export interface CaRow {
  kind: CaKind;
  id: string;
  name: string;
  /** What tells it apart beside its name: its root's subject, or its config string. */
  identity: string;
  /** What it issues through, such as "2 Issuing CAs" or "5 templates", and a line more on it. */
  issuesThrough: string;
  issuesThroughDetail: string;
  permittedNames: string;
  health: Health;
  /** When its CA certificate ends (the root's, for one the platform runs); none before it has one. */
  expires: string | null;
}

const count = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
const ISSUING_STATUS_WORDS: Record<IssuingCa["status"], string> = { active: "active", awaiting_signature: "awaiting signature", retired: "retired", revoked: "revoked" };

export function platformRow(ca: PrivateCa, now: Date): CaRow {
  const byStatus = (["active", "awaiting_signature", "retired", "revoked"] as const)
    .map((status) => [status, ca.issuingCas.filter((i) => i.status === status).length] as const)
    .filter(([, n]) => n > 0)
    .map(([status, n]) => `${n} ${ISSUING_STATUS_WORDS[status]}`);
  // Those that issue, or will: a retired or revoked one's rules no longer bear on anything.
  const live = ca.issuingCas.filter((i) => i.status === "active" || i.status === "awaiting_signature");
  const labels = [...new Set((live.length > 0 ? live : ca.issuingCas).map((i) => permittedNamesLabel(i.permittedNames)))];
  return {
    kind: "platform",
    id: ca.id,
    name: ca.name,
    identity: ca.root?.subject ?? "The Organization's own root, not uploaded yet",
    issuesThrough: count(ca.issuingCas.length, "Issuing CA"),
    issuesThroughDetail: byStatus.join(" · "),
    permittedNames: labels.length === 1 ? labels[0]! : "Set per Issuing CA",
    health: healthOf(platformAttention(ca, now), ca.status === "revoked"),
    expires: ca.root?.notAfter ?? null,
  };
}

/** The templates of an ADCS CA offered for anything: for TLS, for devices, or both. */
export const offeredTemplateIds = (ca: Pick<AdcsCa, "offered">) => new Set([...ca.offered.tls, ...ca.offered.devices]);

export function adcsRow(ca: AdcsCa): CaRow {
  return {
    kind: "adcs",
    id: ca.id,
    name: ca.name,
    identity: ca.configString,
    issuesThrough: count(ca.templates.length, "template"),
    issuesThroughDetail: `${offeredTemplateIds(ca).size} offered · through ${count(ca.agentIds.length, "Agent")}`,
    permittedNames: ca.permittedNames ? permittedNamesLabel(ca.permittedNames) : "None: Approval alone decides",
    health: healthOf(adcsAttention(ca)),
    expires: ca.caCertificate.notAfter,
  };
}

/** The page's rows: those the platform runs, then the ADCS CAs, each by name. */
export function caRows(platform: PrivateCa[], adcs: AdcsCa[], now: Date): CaRow[] {
  const byName = (a: CaRow, b: CaRow) => a.name.localeCompare(b.name);
  return [...platform.map((ca) => platformRow(ca, now)).sort(byName), ...adcs.map(adcsRow).sort(byName)];
}

/** Everything that needs attention across the CAs, worst first. */
export const allAttention = (platform: PrivateCa[], adcs: AdcsCa[], now: Date) => worstFirst([...platform.flatMap((ca) => platformAttention(ca, now)), ...adcs.flatMap(adcsAttention)]);

/** An ADCS CA's templates as its Templates tab groups them: available ones not hidden, those hidden, and those unavailable. */
export function templateGroups<T extends { available: boolean; hidden: boolean }>(templates: T[]) {
  return {
    available: templates.filter((t) => t.available && !t.hidden),
    hidden: templates.filter((t) => t.hidden),
    unavailable: templates.filter((t) => !t.available && !t.hidden),
  };
}
