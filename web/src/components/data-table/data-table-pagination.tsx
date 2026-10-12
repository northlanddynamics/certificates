import { ChevronLeftIcon, ChevronRightIcon, ChevronsLeftIcon, ChevronsRightIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

const PAGE_SIZES = [10, 25, 50, 100];

/** Where the table is in what the server has, and the means to move: `pageIndex` counts from 0. */
export function DataTablePagination({
  pageIndex,
  pageSize,
  rowCount,
  onPageIndexChange,
  onPageSizeChange,
}: {
  pageIndex: number;
  pageSize: number;
  rowCount: number;
  onPageIndexChange: (pageIndex: number) => void;
  onPageSizeChange: (pageSize: number) => void;
}) {
  const pageCount = Math.max(1, Math.ceil(rowCount / pageSize));
  const first = rowCount === 0 ? 0 : pageIndex * pageSize + 1;
  const last = Math.min(rowCount, (pageIndex + 1) * pageSize);
  return (
    <div className="flex flex-wrap items-center justify-between gap-4 px-2 text-sm">
      <p className="text-muted-foreground">
        {first}–{last} of {rowCount}
      </p>
      <div className="flex flex-wrap items-center gap-6 lg:gap-8">
        <div className="flex items-center gap-2">
          <span className="font-medium">Rows per page</span>
          <Select value={String(pageSize)} onValueChange={(v) => onPageSizeChange(Number(v))}>
            <SelectTrigger size="sm" className="w-20" aria-label="Rows per page">
              <SelectValue />
            </SelectTrigger>
            <SelectContent side="top">
              {PAGE_SIZES.map((size) => (
                <SelectItem key={size} value={String(size)}>
                  {size}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <span className="font-medium">
          Page {pageIndex + 1} of {pageCount}
        </span>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="icon-sm" aria-label="First page" disabled={pageIndex === 0} onClick={() => onPageIndexChange(0)}>
            <ChevronsLeftIcon />
          </Button>
          <Button variant="outline" size="icon-sm" aria-label="Previous page" disabled={pageIndex === 0} onClick={() => onPageIndexChange(pageIndex - 1)}>
            <ChevronLeftIcon />
          </Button>
          <Button variant="outline" size="icon-sm" aria-label="Next page" disabled={pageIndex >= pageCount - 1} onClick={() => onPageIndexChange(pageIndex + 1)}>
            <ChevronRightIcon />
          </Button>
          <Button variant="outline" size="icon-sm" aria-label="Last page" disabled={pageIndex >= pageCount - 1} onClick={() => onPageIndexChange(pageCount - 1)}>
            <ChevronsRightIcon />
          </Button>
        </div>
      </div>
    </div>
  );
}
