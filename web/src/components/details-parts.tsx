import type { ReactNode } from "react";
import { CopyButton } from "@/components/copy-button";
import { Badge } from "@/components/ui/badge";
import type { SubjectField } from "@/lib/pki-common";

/** Label and value pairs, one to a row, stacked on a phone. */
export function Rows({ children }: { children: ReactNode }) {
  return <dl className="grid grid-cols-1 gap-x-4 gap-y-1 text-sm sm:grid-cols-[10rem_1fr]">{children}</dl>;
}

export function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <>
      <dt className="text-muted-foreground sm:py-1">{label}</dt>
      <dd className="mb-2 min-w-0 sm:mb-0 sm:py-1">{children}</dd>
    </>
  );
}

/** A value to read off and copy, such as a fingerprint. */
export function Mono({ text, label }: { text: string; label: string }) {
  return (
    <span className="flex items-start gap-1">
      <code className="min-w-0 font-mono text-xs break-all">{text}</code>
      <CopyButton text={text} label={`Copy the ${label}`} />
    </span>
  );
}

/** A subject's or issuer's fields, one to a row. */
export function SubjectRows({ fields }: { fields: SubjectField[] }) {
  if (fields.length === 0) return <p className="text-sm text-muted-foreground">Empty.</p>;
  return (
    <Rows>
      {fields.map((field, i) => (
        <Row key={`${field.type}-${i}`} label={field.type === field.label ? field.type : `${field.label} (${field.type})`}>
          <span className="break-all">{field.value}</span>
        </Row>
      ))}
    </Rows>
  );
}

/** The extensions of a CSR or certificate, and what each says. */
export function ExtensionRows({ extensions }: { extensions: { oid: string; label: string; critical: boolean; summary: string }[] }) {
  return (
    <>
      {extensions.map((extension) => (
        <Row key={extension.oid} label={extension.label}>
          <span className="break-words">{extension.summary}</span>
          {extension.critical && (
            <Badge variant="outline" className="ml-2">
              critical
            </Badge>
          )}
        </Row>
      ))}
    </>
  );
}
