export { cn } from "cn"

/** A date as the viewer's locale writes it. */
export const date = (iso: string) => new Date(iso).toLocaleDateString();
