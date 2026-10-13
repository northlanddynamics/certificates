// What a Deployment Script can be written for. A new interpreter is an entry here, which the database check on
// `deployment_script.interpreter` (schema.ts) must list too.
export const SCRIPT_INTERPRETERS = ["bash", "powershell"] as const;
export type ScriptInterpreter = (typeof SCRIPT_INTERPRETERS)[number];
