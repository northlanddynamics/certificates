import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import type { ScriptParameter } from "@/lib/api";

/**
 * The value each parameter `declared` is shown with, by name: what was typed for its name, else its default, else blank.
 * `typed` may hold names the version does not declare (typed for another version), which are left out, so a value is
 * kept across a version switch only for a name both versions declare. A blank value is sent as it is: the server then
 * applies the default, or leaves the parameter unset.
 */
export function shownValues(declared: ScriptParameter[], typed: Record<string, string>): Record<string, string> {
  return Object.fromEntries(declared.map((p) => [p.name, typed[p.name] ?? p.default ?? ""]));
}

/** The required parameters with neither a value nor a default, which the server would refuse, so the form stops first. */
export function missingParameters(declared: ScriptParameter[], values: Record<string, string>): string[] {
  return declared.filter((p) => p.required && [values[p.name], p.default].every((v) => (v ?? "").trim() === "")).map((p) => p.name);
}

/** Whether the server's `problems` name a parameter `declared`, so they show against its field and not as a message of their own. */
export function namesDeclared(declared: ScriptParameter[], problems: Record<string, string> | undefined): boolean {
  return Object.keys(problems ?? {}).some((name) => declared.some((p) => p.name === name));
}

/**
 * One text input for each parameter a Deployment Script version declares: its label, its description as help, a marker
 * when it is required and its default pre-filled. `problems` is what the server said is wrong with each, by name.
 */
export function ParameterFields({
  declared,
  typed,
  onChange,
  problems = {},
  idPrefix,
}: {
  declared: ScriptParameter[];
  /** What was typed, by name: a name not in it shows its default, and a required one in it left blank is shown as missing. */
  typed: Record<string, string>;
  onChange: (name: string, value: string) => void;
  problems?: Record<string, string>;
  idPrefix: string;
}) {
  const values = shownValues(declared, typed);
  const missing = missingParameters(declared, values);
  return (
    <FieldGroup>
      {declared.map((p) => {
        const id = `${idPrefix}-parameter-${p.name}`;
        const problem = problems[p.name] ?? (p.name in typed && missing.includes(p.name) ? "is required" : undefined);
        return (
          <Field key={p.name} data-invalid={problem !== undefined}>
            <FieldLabel htmlFor={id}>
              {p.label}
              {p.required && <span className="font-normal text-muted-foreground">(required)</span>}
            </FieldLabel>
            <Input id={id} value={values[p.name]} placeholder={p.default} aria-required={p.required} aria-invalid={problem !== undefined} onChange={(e) => onChange(p.name, e.target.value)} />
            <FieldDescription>
              {p.description && <>{p.description} </>}
              The script finds it in <code>DEPLOY_PARAM_{p.name}</code>
              {/* What a blank does, as the server applies it: the default, or nothing at all. */}
              {!p.required && (p.default?.trim() ? "; left blank, it is given the default." : "; left blank, it is not set at all.")}
              {p.required && "."}
            </FieldDescription>
            {problem && (
              <FieldError>
                {p.label} {problem}.
              </FieldError>
            )}
          </Field>
        );
      })}
    </FieldGroup>
  );
}
