import type { ReactTable, TableFeatures } from "@tanstack/react-table";
import type { ReactNode } from "react";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

/**
 * The rows the table was given, in a bordered table. A table whose rows open (the `rowExpandingFeature`, with
 * `getRowCanExpand`) says what is under an open one with `details`; `empty` is what shows when there are no rows.
 */
export function DataTable<TFeatures extends TableFeatures, TData extends object>({
  table,
  empty,
  details,
}: {
  table: ReactTable<TFeatures, TData, any>;
  empty: ReactNode;
  details?: (row: TData) => ReactNode;
}) {
  const rows = table.getRowModel().rows;
  const columnCount = table.getAllLeafColumns().length;
  return (
    <div className="rounded-md border">
      <Table>
        <TableHeader>
          {table.getHeaderGroups().map((group) => (
            <TableRow key={group.id}>
              {group.headers.map((header) => (
                <TableHead key={header.id}>{header.isPlaceholder ? null : <table.FlexRender header={header} />}</TableHead>
              ))}
            </TableRow>
          ))}
        </TableHeader>
        <TableBody>
          {rows.map((row) => {
            // Only a table with the `rowExpandingFeature` has rows that open.
            const open = details !== undefined && (row as unknown as { getIsExpanded(): boolean }).getIsExpanded();
            return (
              <RowAndDetails key={row.id} open={open} columnCount={columnCount} details={open ? details(row.original) : null}>
                {row.getAllCells().map((cell) => (
                  <TableCell key={cell.id}>
                    <table.FlexRender cell={cell} />
                  </TableCell>
                ))}
              </RowAndDetails>
            );
          })}
          {rows.length === 0 && (
            <TableRow>
              <TableCell colSpan={columnCount} className="h-24 text-center text-muted-foreground">
                {empty}
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
    </div>
  );
}

/** A row and, under it while it is open, its details across the whole width. */
function RowAndDetails({ open, columnCount, details, children }: { open: boolean; columnCount: number; details: ReactNode; children: ReactNode }) {
  return (
    <>
      <TableRow data-state={open ? "selected" : undefined}>{children}</TableRow>
      {open && (
        <TableRow className="hover:bg-transparent">
          <TableCell colSpan={columnCount} className="whitespace-normal bg-muted/30 p-4">
            {details}
          </TableCell>
        </TableRow>
      )}
    </>
  );
}
