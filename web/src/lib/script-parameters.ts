// The parameters a Deployment Script declares, read as the platform reads them at upload: these rules are a copy of
// `declaredParameters` in server/src/deployment/script-parameters.ts (the web package shares no code with the server,
// and that one leans on zod and Buffer), and server/test/script-parameters-web.test.ts holds the two to each other.
// The server stays the authority: this only lets the upload form show what a section declares, or why it cannot be used,
// before it is sent.
import type { ScriptParameter } from "./api";

const BEGIN = "# deploy-params:begin";
const END = "# deploy-params:end";
/** What a parameter's name is given after, as the script's environment variable. */
export const ENV_PREFIX = "DEPLOY_PARAM_";
const NAME = /^[A-Z][A-Z0-9_]*$/;
export const MAX_PARAMETERS = 20;
export const MAX_VALUE_BYTES = 1024;
const FIELDS = new Set(["name", "label", "description", "required", "default"]);

/** Why `value` cannot be put in an environment variable, or nothing when it can. */
function valueProblem(value: string): string | undefined {
  if (new TextEncoder().encode(value).length > MAX_VALUE_BYTES) return `is over ${MAX_VALUE_BYTES / 1024} KiB`;
  if (value.includes("\u0000")) return "contains a NUL character";
  if (/[\r\n]/.test(value)) return "contains a newline";
  return undefined;
}

/** What `content` declares, or why the upload would be refused: the server's message, less its exact JSON and schema detail. */
export type Declaration = { parameters: ScriptParameter[]; problem?: undefined } | { parameters?: undefined; problem: string };

export function readDeclaration(content: string): Declaration {
  const lines = content.split(/\r?\n/).map((line) => line.trim());
  const begins = lines.flatMap((line, i) => (line === BEGIN ? [i] : []));
  const ends = lines.flatMap((line, i) => (line === END ? [i] : []));
  if (begins.length > 1) return { problem: `a script has one parameter section, not more than one` };
  const [begin] = begins;
  if (begin === undefined) {
    if (ends.length > 0) return { problem: `a "${END}" line ends no section: it needs a "${BEGIN}" line before it` };
    return { parameters: [] };
  }
  const end = ends.find((i) => i > begin);
  if (end === undefined || ends.length > 1) return { problem: `the parameter section needs exactly one "${END}" line after its "${BEGIN}" line` };
  const stray = lines.findIndex((line, i) => i > begin && i < end && line !== "" && !line.startsWith("#"));
  if (stray !== -1) return { problem: `line ${stray + 1} is inside the parameter section but is not a comment: start it with "# "` };
  const inside = lines.slice(begin + 1, end).map((line) => line.replace(/^# ?/, ""));

  let json: unknown;
  try {
    json = JSON.parse(inside.join("\n"));
  } catch (err) {
    return { problem: `the parameter section is not JSON: ${(err as Error).message}` };
  }
  const shape = arrayOfParameters(json);
  if (typeof shape === "string") return { problem: `the parameter section must be a JSON array of parameters: ${shape}` };
  if (shape.length > MAX_PARAMETERS) return { problem: `a script declares at most ${MAX_PARAMETERS} parameters, not ${shape.length}` };
  const seen = new Set<string>();
  for (const { name, default: fallback } of shape) {
    if (!NAME.test(name)) return { problem: `the parameter name "${name}" must be upper-case letters, digits and _, starting with a letter` };
    if (name.startsWith(ENV_PREFIX)) return { problem: `the parameter name "${name}" must not start with ${ENV_PREFIX}: the script is given it with that prefix already` };
    if (seen.has(name)) return { problem: `the parameter "${name}" is declared more than once` };
    seen.add(name);
    const problem = fallback === undefined ? undefined : valueProblem(fallback);
    if (problem) return { problem: `the default of the parameter "${name}" ${problem}` };
  }
  return {
    parameters: shape.map((p) => ({
      name: p.name,
      label: p.label?.trim() ? p.label : p.name,
      description: p.description ?? "",
      required: p.required ?? false,
      ...(p.default === undefined ? {} : { default: p.default }),
    })),
  };
}

type Declared = { name: string; label?: string; description?: string; required?: boolean; default?: string };

/** `json` as the parameters it declares, or what is wrong with its shape. */
function arrayOfParameters(json: unknown): Declared[] | string {
  if (!Array.isArray(json)) return "it is not an array";
  for (const [i, p] of json.entries()) {
    if (typeof p !== "object" || p === null || Array.isArray(p)) return `entry ${i + 1} is not an object`;
    const entry = p as Record<string, unknown>;
    const unknown = Object.keys(entry).find((key) => !FIELDS.has(key));
    if (unknown !== undefined) return `entry ${i + 1} has a field "${unknown}", which is not one of name, label, description, required and default`;
    if (typeof entry.name !== "string") return `entry ${i + 1} needs a "name" that is a string`;
    for (const key of ["label", "description", "default"] as const)
      if (entry[key] !== undefined && typeof entry[key] !== "string") return `the "${key}" of entry ${i + 1} must be a string`;
    if (entry.required !== undefined && typeof entry.required !== "boolean") return `the "required" of entry ${i + 1} must be true or false`;
  }
  return json as Declared[];
}

/**
 * The value each parameter `declared` gives the script from `values`, by name, as the server keeps it: a blank value takes
 * the default, and one still blank is absent, so the script finds it unset.
 */
export function givenValues(declared: ScriptParameter[], values: Record<string, string>): Record<string, string> {
  const given: Record<string, string> = {};
  for (const p of declared) {
    const value = [values[p.name], p.default].find((v) => v !== undefined && v.trim() !== "");
    if (value !== undefined) given[p.name] = value;
  }
  return given;
}
