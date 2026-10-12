import { ChevronRightIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

/** The control that opens a row of a table to its details; `what` names the row for those who cannot see it. */
export function ExpandButton({ open, what, onToggle }: { open: boolean; what: string; onToggle: () => void }) {
  return (
    <Button variant="ghost" size="icon-sm" aria-label={`${open ? "Hide" : "Show"} details of ${what}`} aria-expanded={open} onClick={onToggle}>
      <ChevronRightIcon className={cn("transition-transform", open && "rotate-90")} />
    </Button>
  );
}
