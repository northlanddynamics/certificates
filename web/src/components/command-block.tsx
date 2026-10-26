import { CopyButton } from "@/components/copy-button";
import { ScriptCode } from "@/components/script-code";
import type { DeploymentScript } from "@/lib/api";

/** Commands, or a file's content, for the reader to copy and run: coloured for the shell, with a button that copies it. */
export function CommandBlock({ code, shell, label }: { code: string; shell: DeploymentScript["interpreter"]; label: string }) {
  return (
    <div className="relative">
      <ScriptCode code={code} interpreter={shell} label={label} className="pr-9" />
      <div className="absolute top-1.5 right-1.5">
        <CopyButton text={code} label={`Copy: ${label}`} />
      </div>
    </div>
  );
}
