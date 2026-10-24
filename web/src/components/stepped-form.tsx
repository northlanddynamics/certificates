import { CheckIcon, CircleAlertIcon, type LucideIcon } from "lucide-react";
import { useState, type FormEvent, type ReactNode } from "react";
import { Breadcrumb, BreadcrumbItem, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb";
import { Button } from "@/components/ui/button";
import { Sidebar, SidebarContent, SidebarGroup, SidebarGroupContent, SidebarMenu, SidebarMenuButton, SidebarMenuItem, SidebarProvider } from "@/components/ui/sidebar";

/** The dialog that holds a stepped form. */
export const STEPPED_DIALOG = "gap-0 overflow-hidden p-0 sm:max-w-[calc(100%-2rem)] md:max-w-[760px] lg:max-w-[860px]";

export type Step<Id extends string> = { id: Id; title: string; icon: LucideIcon };

/** What a step still needs, in a sentence that says what to do, and the id of the field to give it in, if there is one. */
export type Missing = { reason: string; field?: string };

/**
 * Moving through `steps`: which is open and whether it is the last, which are complete (`missing` says nothing for
 * them) and may be opened, and Next, which opens the next one or, on one that is not complete, first lets the step's
 * `resolve` complete it (such as by making a key), and otherwise keeps it open and says what it needs (`told`, until
 * another step opens) and moves to that field.
 */
export function useSteps<Id extends string>(
  steps: readonly { id: Id }[],
  step: Id,
  onStep: (step: Id) => void,
  missing: Partial<Record<Id, Missing | undefined>>,
  resolve: Partial<Record<Id, () => Promise<boolean>>> = {},
) {
  // A step that has gone from `steps` since it was opened leaves the first one showing.
  const index = Math.max(0, steps.findIndex((s) => s.id === step));
  const last = index === steps.length - 1;
  const complete = (id: Id) => !missing[id];
  const reachable = (i: number) => steps.slice(0, i).every((s) => complete(s.id));
  // The step whose Next was pressed before it was complete.
  const [toldFor, setToldFor] = useState<Id | null>(null);
  const current = steps[index]!;
  const goTo = (i: number) => {
    const target = steps[i];
    if (target && reachable(i)) {
      setToldFor(null);
      onStep(target.id);
    }
  };
  // While a step's `resolve` does what Next asked of it, such as making a key.
  const [resolving, setResolving] = useState(false);
  const next = async () => {
    const needs = missing[current.id];
    if (!needs) return goTo(index + 1);
    const resolver = resolve[current.id];
    if (resolver && !resolving) {
      setResolving(true);
      try {
        // It is complete once resolved, though `missing` says so only on the next render.
        if (await resolver()) {
          setToldFor(null);
          const target = steps[index + 1];
          if (target) onStep(target.id);
          return;
        }
      } finally {
        setResolving(false);
      }
    }
    setToldFor(current.id);
    if (needs.field) document.getElementById(needs.field)?.focus();
  };
  return { index, last, complete, reachable, goTo, next, resolving, told: toldFor === current.id ? missing[current.id] : undefined };
}

/** What the open step still needs, beside its Next once Next has been pressed; empty otherwise, and announced when it changes. */
export function StepReason({ missing }: { missing: Missing | undefined }) {
  return (
    <p role="status" className="flex min-w-0 flex-1 items-center justify-end gap-1.5 text-right text-sm text-destructive">
      {missing && (
        <>
          <CircleAlertIcon className="size-4 shrink-0" aria-hidden />
          {missing.reason}
        </>
      )}
    </p>
  );
}

/**
 * A form in steps: the steps down the side, one shown at a time, Back and Next below. A step is complete unless
 * `missing` says what it still needs, and may be opened once every step before it is complete; submitting the last one
 * calls `onSubmit`. Next on a step that is not complete says what it needs and moves to that field, rather than being
 * greyed out with no reason. `tall` is for a form whose steps need more room.
 */
export function SteppedForm<Id extends string>({
  title,
  steps,
  step,
  onStep,
  missing,
  resolve,
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
  missing: Partial<Record<Id, Missing | undefined>>;
  /** For a step that Next can complete itself: does so, and says whether it did. */
  resolve?: Partial<Record<Id, () => Promise<boolean>>>;
  submitLabel: string;
  pending: boolean;
  onSubmit: () => void;
  tall?: boolean;
  children: ReactNode;
}) {
  const { index, last, complete, reachable, goTo, next, resolving, told } = useSteps(steps, step, onStep, missing, resolve);
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
                      {i < index && complete(s.id) ? <CheckIcon className="text-primary" /> : <s.icon />}
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
          if (!last) void next();
          else if (steps.every((s) => complete(s.id))) onSubmit();
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
          <StepReason missing={told} />
          {last ? (
            <Button key="submit" type="submit" disabled={pending}>
              {submitLabel}
            </Button>
          ) : (
            <Button key="next" type="button" disabled={resolving} onClick={() => void next()}>
              {resolving ? "Working…" : "Next"}
            </Button>
          )}
        </footer>
      </form>
    </SidebarProvider>
  );
}
