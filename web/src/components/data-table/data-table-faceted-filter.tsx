import { CheckIcon, PlusCircleIcon } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Command, CommandEmpty, CommandGroup, CommandItem, CommandList, CommandSeparator } from "@/components/ui/command";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Separator } from "@/components/ui/separator";
import { cn } from "@/lib/utils";

export interface FacetOption {
  value: string;
  label: string;
}

/** A button that opens a list of values to narrow the table by; the values chosen show on the button. */
export function DataTableFacetedFilter({
  title,
  options,
  value,
  onChange,
  hint,
}: {
  title: string;
  options: FacetOption[];
  value: string[];
  onChange: (value: string[]) => void;
  /** What choosing several does, when that is not obvious. */
  hint?: string;
}) {
  const selected = new Set(value);
  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="outline" size="sm" className="border-dashed">
          <PlusCircleIcon />
          {title}
          {selected.size > 0 && (
            <>
              <Separator orientation="vertical" className="mx-1 data-[orientation=vertical]:h-4" />
              <Badge variant="secondary" className="rounded-sm px-1 font-normal lg:hidden">
                {selected.size}
              </Badge>
              <span className="hidden gap-1 lg:flex">
                {selected.size > 2 ? (
                  <Badge variant="secondary" className="rounded-sm px-1 font-normal">
                    {selected.size} selected
                  </Badge>
                ) : (
                  options
                    .filter((o) => selected.has(o.value))
                    .map((o) => (
                      <Badge key={o.value} variant="secondary" className="rounded-sm px-1 font-normal">
                        {o.label}
                      </Badge>
                    ))
                )}
              </span>
            </>
          )}
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-56 p-0" align="start">
        <Command>
          <CommandList>
            <CommandEmpty>No results.</CommandEmpty>
            <CommandGroup>
              {options.map((option) => {
                const isSelected = selected.has(option.value);
                return (
                  <CommandItem
                    key={option.value}
                    onSelect={() => onChange(isSelected ? value.filter((v) => v !== option.value) : [...value, option.value])}
                  >
                    <div
                      className={cn(
                        "flex size-4 items-center justify-center rounded-[4px] border border-primary",
                        isSelected ? "bg-primary text-primary-foreground" : "opacity-50 [&_svg]:invisible",
                      )}
                    >
                      <CheckIcon className="size-3.5 text-primary-foreground" />
                    </div>
                    <span>{option.label}</span>
                  </CommandItem>
                );
              })}
            </CommandGroup>
            {selected.size > 0 && (
              <>
                <CommandSeparator />
                <CommandGroup>
                  <CommandItem onSelect={() => onChange([])} className="justify-center text-center">
                    Clear
                  </CommandItem>
                </CommandGroup>
              </>
            )}
          </CommandList>
          {hint && <p className="border-t px-3 py-2 text-xs text-muted-foreground">{hint}</p>}
        </Command>
      </PopoverContent>
    </Popover>
  );
}
