import type { ReactNode } from "react";

/** The review step of a form: what was entered, a label and its value to a row. */
export function SummaryRows({ rows }: { rows: { label: string; value: ReactNode }[] }) {
  return (
    <div className="rounded-md border p-4">
      <dl className="grid grid-cols-[9rem_1fr] gap-x-4 gap-y-3 text-sm">
        {rows.map(({ label, value }) => (
          <div key={label} className="col-span-2 grid grid-cols-subgrid items-baseline">
            <dt className="text-muted-foreground">{label}</dt>
            <dd className="min-w-0 break-words">{value}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}
