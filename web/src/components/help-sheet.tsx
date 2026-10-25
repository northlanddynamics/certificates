import type { ReactNode, RefObject } from "react";
import { Sheet, SheetContent, SheetDescription, SheetTitle } from "@/components/ui/sheet";

/** The help panel's frame: a wide sheet from the right, over the page and any dialog on it, its body scrolling on its own. */
export function HelpSheet({
  open,
  onClose,
  title,
  description,
  bodyRef,
  children,
}: {
  open: boolean;
  onClose: () => void;
  /** What a screen reader announces it as. */
  title: string;
  description: string;
  bodyRef?: RefObject<HTMLDivElement | null>;
  children: ReactNode;
}) {
  return (
    <Sheet open={open} onOpenChange={(next) => !next && onClose()}>
      <SheetContent side="right" className="w-full gap-0 data-[side=right]:w-full data-[side=right]:sm:max-w-2xl">
        <SheetTitle className="sr-only">{title}</SheetTitle>
        <SheetDescription className="sr-only">{description}</SheetDescription>
        <div ref={bodyRef} className="min-h-0 flex-1 overflow-y-auto p-6">
          {children}
        </div>
      </SheetContent>
    </Sheet>
  );
}
