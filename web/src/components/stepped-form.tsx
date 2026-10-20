import { CheckIcon, type LucideIcon } from "lucide-react";
import type { FormEvent, ReactNode } from "react";
import { Breadcrumb, BreadcrumbItem, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb";
import { Button } from "@/components/ui/button";
import { Sidebar, SidebarContent, SidebarGroup, SidebarGroupContent, SidebarMenu, SidebarMenuButton, SidebarMenuItem, SidebarProvider } from "@/components/ui/sidebar";

/** The dialog that holds a stepped form. */
export const STEPPED_DIALOG = "gap-0 overflow-hidden p-0 sm:max-w-[calc(100%-2rem)] md:max-w-[760px] lg:max-w-[860px]";

export type Step<Id extends string> = { id: Id; title: string; icon: LucideIcon };

/**
 * A form in steps: the steps down the side, one shown at a time, Back and Next below. A step may be opened once every
 * step before it is complete; submitting the last one calls `onSubmit`. `tall` is for a form whose steps need more room.
 */
export function SteppedForm<Id extends string>({
  title,
  steps,
  step,
  onStep,
  complete,
  submitLabel,
  pending,
  onSubmit,
  tall = false,
  children,
}: {
  title: string;
  steps: readonly Step<Id>[];
  step: Id;
  onStep: (step: Id) => void;
  complete: Record<Id, boolean>;
  submitLabel: string;
  pending: boolean;
  onSubmit: () => void;
  tall?: boolean;
  children: ReactNode;
}) {
  // A step that has gone from `steps` since it was opened leaves the first one showing.
  const index = Math.max(0, steps.findIndex((s) => s.id === step));
  const last = index === steps.length - 1;
  const reachable = (i: number) => steps.slice(0, i).every((s) => complete[s.id]);
  const goTo = (i: number) => {
    const target = steps[i];
    if (target && reachable(i)) onStep(target.id);
  };
  return (
    <SidebarProvider className={tall ? "h-[min(640px,85vh)] min-h-0 items-stretch" : "h-[min(600px,85vh)] min-h-0 items-stretch"}>
      <Sidebar collapsible="none" className="hidden border-r md:flex">
        <SidebarContent>
          <SidebarGroup>
            <SidebarGroupContent>
              <SidebarMenu>
                {steps.map((s, i) => (
                  <SidebarMenuItem key={s.id}>
                    <SidebarMenuButton isActive={s.id === step} disabled={!reachable(i)} onClick={() => goTo(i)}>
                      {i < index && complete[s.id] ? <CheckIcon className="text-primary" /> : <s.icon />}
                      <span>{s.title}</span>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                ))}
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
        </SidebarContent>
      </Sidebar>
      <form
        className="flex min-w-0 flex-1 flex-col"
        onSubmit={(e: FormEvent) => {
          e.preventDefault();
          if (!last) goTo(index + 1);
          else if (steps.every((s) => complete[s.id])) onSubmit();
        }}
      >
        <header className="flex h-14 shrink-0 items-center justify-between gap-2 px-4 pr-12">
          <Breadcrumb>
            <BreadcrumbList>
              <BreadcrumbItem className="hidden md:block">{title}</BreadcrumbItem>
              <BreadcrumbSeparator className="hidden md:block" />
              <BreadcrumbItem>
                <BreadcrumbPage>{steps[index]?.title}</BreadcrumbPage>
              </BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
          <span className="text-xs text-muted-foreground">
            Step {index + 1} of {steps.length}
          </span>
        </header>
        <div className="flex flex-1 flex-col gap-4 overflow-y-auto p-4 pt-0">{children}</div>
        <footer className="flex shrink-0 items-center justify-between gap-2 border-t bg-muted/50 p-4">
          <Button type="button" variant="outline" disabled={index === 0} onClick={() => goTo(index - 1)}>
            Back
          </Button>
          {last ? (
            <Button key="submit" type="submit" disabled={pending}>
              {submitLabel}
            </Button>
          ) : (
            <Button key="next" type="button" disabled={!complete[steps[index]!.id]} onClick={() => goTo(index + 1)}>
              Next
            </Button>
          )}
        </footer>
      </form>
    </SidebarProvider>
  );
}
