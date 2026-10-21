export { cn } from "cn"

/**
 * Lets a table's cells, and the long names in them, wrap to fit the box rather than run past it or keep the table
 * wider than a phone: on the element around the table.
 */
export const WRAPPING_TABLE = "[&_td]:whitespace-normal [&_td]:[overflow-wrap:anywhere] [&_th]:whitespace-normal";

/** A date as the viewer's locale writes it. */
export const date = (iso: string) => new Date(iso).toLocaleDateString();
