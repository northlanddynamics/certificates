import { Checkbox } from "@/components/ui/checkbox";
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel, FieldLegend, FieldSet } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import type { NameRules } from "@/lib/api";

// Name Rules, as an Organization Administrator writes them: optional limits on the names a device may ask for under a
// profile whose Enrollment Validator does not vouch for names. Left empty, the profile has none and issues the names a
// device asks for within its Issuing CA's permitted name rules. The server checks them too (server/src/name-rules.ts).

type SanType = NameRules["allowedSanTypes"][number];
const SAN_TYPES = ["dns", "email", "ip", "url", "upn"] as const satisfies readonly SanType[];
const SAN_LABEL: Record<SanType, string> = { dns: "DNS name", email: "Email address", ip: "IP address", url: "URI", upn: "UPN" };
const ATTRIBUTE = /^([A-Za-z][A-Za-z0-9-]*|\d+(\.\d+)+)$/;

/** Name Rules as typed: comma-separated attributes and patterns, one subject attribute's patterns a line. */
export interface NameRulesDraft {
  required: string;
  subject: string;
  sanTypes: SanType[];
  sanPatterns: Partial<Record<SanType, string>>;
}

export const EMPTY_NAME_RULES: NameRulesDraft = { required: "", subject: "", sanTypes: [], sanPatterns: {} };

const list = (text: string) =>
  text
    .split(",")
    .map((item) => item.trim())
    .filter((item) => item !== "");

export function draftOf(rules: NameRules | null): NameRulesDraft {
  if (!rules) return EMPTY_NAME_RULES;
  return {
    required: rules.requiredSubjectAttributes.join(", "),
    subject: Object.entries(rules.subjectPatterns)
      .map(([attribute, patterns]) => `${attribute} = ${patterns.join(", ")}`)
      .join("\n"),
    sanTypes: rules.allowedSanTypes,
    sanPatterns: Object.fromEntries(Object.entries(rules.sanPatterns).map(([type, patterns]) => [type, patterns.join(", ")])),
  };
}

/** The rules the draft says, none when it is empty, or what is wrong with it. */
export function rulesOf(draft: NameRulesDraft): { rules: NameRules | null } | { error: string } {
  const required = list(draft.required).map((a) => a.toUpperCase());
  const subjectPatterns: Record<string, string[]> = {};
  for (const line of draft.subject.split("\n").filter((l) => l.trim() !== "")) {
    const [attribute, patterns, ...rest] = line.split("=");
    const name = attribute!.trim().toUpperCase();
    if (patterns === undefined || rest.length > 0 || !ATTRIBUTE.test(name)) return { error: `Write each subject line as an attribute, =, and its patterns, such as CN = kiosk-*: ${line.trim()}` };
    if (list(patterns).length === 0) return { error: `Give ${name} at least one pattern.` };
    subjectPatterns[name] = [...(subjectPatterns[name] ?? []), ...list(patterns)];
  }
  const unknown = required.find((a) => !ATTRIBUTE.test(a));
  if (unknown) return { error: `${unknown} is not a subject attribute's short name, such as CN, or its OID.` };
  const sanPatterns = Object.fromEntries(draft.sanTypes.flatMap((type) => (list(draft.sanPatterns[type] ?? "").length > 0 ? [[type, list(draft.sanPatterns[type] ?? "")]] : [])));
  if (required.length === 0 && Object.keys(subjectPatterns).length === 0 && draft.sanTypes.length === 0) return { rules: null };
  return { rules: { requiredSubjectAttributes: required, subjectPatterns, allowedSanTypes: draft.sanTypes, sanPatterns } };
}

/** Fields for Name Rules; all empty means the profile has none. */
export function NameRulesEditor({ id, draft, onChange }: { id: string; draft: NameRulesDraft; onChange: (draft: NameRulesDraft) => void }) {
  const parsed = rulesOf(draft);
  return (
    <FieldSet>
      <FieldLegend variant="label">Name Rules (optional)</FieldLegend>
      <FieldDescription>
        This validator does not check the names a device asks for. Leave these empty to issue the subject and names of each device's request, within the Issuing CA's permitted names. Once any is given, a
        subject attribute or name type they do not allow is refused. A pattern matches the whole value, ignoring case, and * stands for anything.
      </FieldDescription>
      <FieldGroup>
        <Field>
          <FieldLabel htmlFor={`${id}-required`}>Required subject attributes</FieldLabel>
          <Input id={`${id}-required`} value={draft.required} onChange={(e) => onChange({ ...draft, required: e.target.value })} placeholder="CN" />
          <FieldDescription>Comma-separated; each may hold any value unless it has patterns below.</FieldDescription>
        </Field>
        <Field>
          <FieldLabel htmlFor={`${id}-subject`}>Subject patterns</FieldLabel>
          <Textarea id={`${id}-subject`} rows={3} className="font-mono text-xs" value={draft.subject} onChange={(e) => onChange({ ...draft, subject: e.target.value })} placeholder={"CN = kiosk-*\nO = Acme"} />
          <FieldDescription>One attribute a line, with the patterns each of its values must match one of.</FieldDescription>
        </Field>
        <FieldSet>
          <FieldLegend variant="label">Subject alternative names allowed</FieldLegend>
          <FieldGroup className="gap-2">
            {SAN_TYPES.map((type) => {
              const on = draft.sanTypes.includes(type);
              return (
                <div key={type} className="grid items-center gap-2 sm:grid-cols-[10rem_1fr]">
                  <Field orientation="horizontal">
                    <Checkbox
                      id={`${id}-san-${type}`}
                      checked={on}
                      onCheckedChange={(checked) => onChange({ ...draft, sanTypes: checked === true ? SAN_TYPES.filter((t) => t === type || draft.sanTypes.includes(t)) : draft.sanTypes.filter((t) => t !== type) })}
                    />
                    <FieldLabel htmlFor={`${id}-san-${type}`} className="font-normal">
                      {SAN_LABEL[type]}
                    </FieldLabel>
                  </Field>
                  {on && (
                    <Input
                      aria-label={`${SAN_LABEL[type]} patterns`}
                      value={draft.sanPatterns[type] ?? ""}
                      onChange={(e) => onChange({ ...draft, sanPatterns: { ...draft.sanPatterns, [type]: e.target.value } })}
                      placeholder="Any, or patterns such as *.devices.example.com"
                    />
                  )}
                </div>
              );
            })}
          </FieldGroup>
        </FieldSet>
      </FieldGroup>
      {"error" in parsed && <FieldError>{parsed.error}</FieldError>}
    </FieldSet>
  );
}

/** The rules as one line for a summary. */
export function nameRulesSummary(rules: NameRules | null) {
  if (!rules) return "None: the names each device asks for, within the Issuing CA's permitted names";
  const subject = [...new Set([...rules.requiredSubjectAttributes, ...Object.keys(rules.subjectPatterns)])].map((a) => (rules.subjectPatterns[a] ? `${a} ${rules.subjectPatterns[a]!.join(" or ")}` : a));
  const sans = rules.allowedSanTypes.map((t) => (rules.sanPatterns[t] ? `${SAN_LABEL[t]} ${rules.sanPatterns[t]!.join(" or ")}` : SAN_LABEL[t]));
  return `Subject: ${subject.join(", ") || "nothing"}. Alternative names: ${sans.join(", ") || "none"}.`;
}
