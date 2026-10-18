// PROTOTYPE (branch prototype/csr-ux): throwaway. Picks a UI variant from `?variant=` and shows a floating bar that
// cycles through them (also with the ← and → keys). Shown only in development builds.
import { useRouter, useRouterState } from "@tanstack/react-router";
import { ChevronLeftIcon, ChevronRightIcon } from "lucide-react";
import { useEffect } from "react";
import { createPortal } from "react-dom";

export interface PrototypeVariant {
  key: string;
  name: string;
}

/** The current variant's key: the `?variant=` one if it is in `variants`, otherwise the first. */
export function usePrototypeVariant(variants: PrototypeVariant[]): string {
  const search = useRouterState({ select: (s) => s.location.searchStr });
  const wanted = new URLSearchParams(search).get("variant");
  return variants.some((v) => v.key === wanted) ? wanted! : variants[0]!.key;
}

/** For a dialog that must stay open when the bar is clicked. */
export const isPrototypeSwitcher = (target: EventTarget | null) => target instanceof Element && target.closest("[data-prototype-switcher]") !== null;

export function PrototypeSwitcher({ title, variants }: { title: string; variants: PrototypeVariant[] }) {
  const router = useRouter();
  const current = usePrototypeVariant(variants);
  const index = variants.findIndex((v) => v.key === current);

  const go = (step: number) => {
    const next = variants[(index + step + variants.length) % variants.length]!;
    const params = new URLSearchParams(window.location.search);
    params.set("variant", next.key);
    router.history.replace(`${window.location.pathname}?${params}`);
  };

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement;
      if (el.closest("input, textarea, select, [contenteditable], [role=combobox], [role=listbox], [role=radiogroup]")) return;
      if (e.key === "ArrowLeft") go(-1);
      if (e.key === "ArrowRight") go(1);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  if (!import.meta.env.DEV) return null;
  return createPortal(
    <div
      data-prototype-switcher
      className="pointer-events-auto fixed bottom-4 left-1/2 z-[100] flex -translate-x-1/2 items-center gap-1 rounded-full bg-fuchsia-700 px-2 py-1.5 text-sm text-white shadow-xl ring-2 ring-white/40"
    >
      <button type="button" className="rounded-full p-1 hover:bg-white/20" aria-label="Previous variant" onClick={() => go(-1)}>
        <ChevronLeftIcon className="size-4" />
      </button>
      <span className="px-2 whitespace-nowrap">
        <span className="opacity-70">PROTOTYPE · {title}:</span> <strong>{current}</strong> ({variants[index]?.name})
      </span>
      <button type="button" className="rounded-full p-1 hover:bg-white/20" aria-label="Next variant" onClick={() => go(1)}>
        <ChevronRightIcon className="size-4" />
      </button>
    </div>,
    document.body,
  );
}
