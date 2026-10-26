import type { ScriptParameter } from "@/lib/api";
import { ENV_PREFIX, givenValues } from "@/lib/script-parameters";

/**
 * The environment a run of a script version declaring `declared` is given. With `values` (what a Deployment's form
 * holds), each parameter shows what the script will see, defaults applied and blanks unset, as the server keeps them;
 * without, what a Deployment of the version would be asked for.
 */
export function ScriptEnvironment({ declared, values }: { declared: ScriptParameter[]; values?: Record<string, string> }) {
  const given = values && givenValues(declared, values);
  return (
    <pre aria-label="Environment" className="overflow-x-auto rounded-md border bg-muted p-3 font-mono text-xs leading-relaxed">
      <span className="text-muted-foreground"># Also set for every run: the CERT_* variables{"\n"}</span>
      {declared.length === 0 && <span className="text-muted-foreground"># This version declares no parameters.</span>}
      {declared.map((p) => {
        const variable = `${ENV_PREFIX}${p.name}`;
        if (given) return given[p.name] === undefined ? <span key={p.name} className="text-muted-foreground">{`# ${variable} is not set\n`}</span> : `${variable}=${given[p.name]}\n`;
        if (p.required) return `${variable}=<required>\n`;
        if (p.default?.trim()) return `${variable}=${p.default}  # unless another value is given\n`;
        return <span key={p.name} className="text-muted-foreground">{`# ${variable} is not set unless a value is given\n`}</span>;
      })}
    </pre>
  );
}
