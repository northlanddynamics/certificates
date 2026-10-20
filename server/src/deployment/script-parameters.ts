// The parameters a Deployment Script version declares: a JSON array in a comment block of its own content, between
// `# deploy-params:begin` and `# deploy-params:end`, each line inside with its leading `# ` removed. `#` starts a comment
// in Bash and PowerShell alike, so one format serves both. The platform reads the block when a version is uploaded and
// keeps what it declares on the version; being content, it is inside the hash and never changes. The Agent never reads it.
import { z } from "@hono/zod-openapi";

const BEGIN = "# deploy-params:begin";
const END = "# deploy-params:end";
/** What a parameter's name is given after, as the script's environment variable. */
const ENV_PREFIX = "DEPLOY_PARAM_";
/** A name that is safe as the rest of an environment variable's name, unquoted, in Bash and PowerShell alike. */
const NAME = /^[A-Z][A-Z0-9_]*$/;
const MAX_PARAMETERS = 20;
const MAX_VALUE_BYTES = 1024;

/** Why `value` cannot be put in an environment variable, or nothing when it can. */
function valueProblem(value: string): string | undefined {
  if (Buffer.byteLength(value, "utf8") > MAX_VALUE_BYTES) return `is over ${MAX_VALUE_BYTES / 1024} KiB`;
  if (value.includes("\u0000")) return "contains a NUL character";
  if (/[\r\n]/.test(value)) return "contains a newline";
  return undefined;
}

export const ScriptParameter = z
  .object({
    name: z.string().openapi({ description: "Upper-case letters, digits and `_`, starting with a letter. The script is given the value as `DEPLOY_PARAM_` and the name." }),
    label: z.string().openapi({ description: "What a person giving the value is shown: the name when the declaration gives none." }),
    description: z.string().openapi({ description: "Help for whoever gives the value." }),
    required: z.boolean(),
    default: z.string().optional().openapi({ description: "Used when no value is given." }),
  })
  .openapi("ScriptParameter");
export type ScriptParameter = z.infer<typeof ScriptParameter>;

/** How a parameter may be written in the section: only `name` is needed. */
const DeclaredParameter = z.strictObject({
  name: z.string(),
  label: z.string().optional(),
  description: z.string().optional(),
  required: z.boolean().optional(),
  default: z.string().optional(),
});

/** The section is there but cannot be used; the message names what is wrong with it. */
export class ScriptParametersError extends Error {}

/** The parameters `content` declares: none when it has no parameter section. */
export function declaredParameters(content: string): ScriptParameter[] {
  const lines = content.split(/\r?\n/).map((line) => line.trim());
  const begins = lines.flatMap((line, i) => (line === BEGIN ? [i] : []));
  const ends = lines.flatMap((line, i) => (line === END ? [i] : []));
  if (begins.length > 1) throw new ScriptParametersError(`a script has one parameter section, not more than one`);
  const [begin] = begins;
  if (begin === undefined) {
    if (ends.length > 0) throw new ScriptParametersError(`a "${END}" line ends no section: it needs a "${BEGIN}" line before it`);
    return [];
  }
  const end = ends.find((i) => i > begin);
  if (end === undefined || ends.length > 1) throw new ScriptParametersError(`the parameter section needs exactly one "${END}" line after its "${BEGIN}" line`);
  // Each line must stay a comment, or the interpreter would run the declaration.
  const stray = lines.findIndex((line, i) => i > begin && i < end && line !== "" && !line.startsWith("#"));
  if (stray !== -1) throw new ScriptParametersError(`line ${stray + 1} is inside the parameter section but is not a comment: start it with "# "`);
  const inside = lines.slice(begin + 1, end).map((line) => line.replace(/^# ?/, ""));

  let json: unknown;
  try {
    json = JSON.parse(inside.join("\n"));
  } catch (err) {
    throw new ScriptParametersError(`the parameter section is not JSON: ${(err as Error).message}`);
  }
  const parsed = z.array(DeclaredParameter).safeParse(json);
  if (!parsed.success) throw new ScriptParametersError(`the parameter section must be a JSON array of parameters: ${z.prettifyError(parsed.error)}`);
  if (parsed.data.length > MAX_PARAMETERS) throw new ScriptParametersError(`a script declares at most ${MAX_PARAMETERS} parameters, not ${parsed.data.length}`);
  const seen = new Set<string>();
  for (const { name, default: fallback } of parsed.data) {
    if (!NAME.test(name)) throw new ScriptParametersError(`the parameter name "${name}" must be upper-case letters, digits and _, starting with a letter`);
    if (name.startsWith(ENV_PREFIX)) throw new ScriptParametersError(`the parameter name "${name}" must not start with ${ENV_PREFIX}: the script is given it with that prefix already`);
    if (seen.has(name)) throw new ScriptParametersError(`the parameter "${name}" is declared more than once`);
    seen.add(name);
    const problem = fallback === undefined ? undefined : valueProblem(fallback);
    if (problem) throw new ScriptParametersError(`the default of the parameter "${name}" ${problem}`);
  }
  return parsed.data.map((p) => ({
    name: p.name,
    label: p.label?.trim() ? p.label : p.name,
    description: p.description ?? "",
    required: p.required ?? false,
    ...(p.default === undefined ? {} : { default: p.default }),
  }));
}
