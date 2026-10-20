import { z } from "@hono/zod-openapi";

export type ErrorStatus = 400 | 401 | 403 | 404 | 409 | 422 | 429 | 502;

export class HttpError extends Error {
  constructor(
    readonly status: ErrorStatus,
    message: string,
    /** More of the error for a program to read, sent beside `error`: such as which fields are at fault. */
    readonly detail?: Record<string, unknown>,
  ) {
    super(message);
  }
}

const UNIQUE_VIOLATION = "23505";
const FOREIGN_KEY_VIOLATION = "23503";
// Drizzle wraps driver errors; the Postgres error code is on the cause.
export const isUniqueViolation = (err: any) => (err?.cause?.code ?? err?.code) === UNIQUE_VIOLATION;
export const isForeignKeyViolation = (err: any) => (err?.cause?.code ?? err?.code) === FOREIGN_KEY_VIOLATION;

const ErrorBody = z.object({ error: z.string() });
export const errors = (...codes: ErrorStatus[]) =>
  Object.fromEntries(
    codes.map((c) => [c, { description: "Error", content: { "application/json": { schema: ErrorBody } } }]),
  );

export const OrgParam = z.object({ orgId: z.string().openapi({ param: { name: "orgId", in: "path" } }) });
export const json = <T extends z.ZodType>(schema: T, description = "OK") => ({
  description,
  content: { "application/json": { schema } },
});

/** The query of a list the server pages: `page` from 1, and how many to a page. The response says `total`, the count in all. */
const DEFAULT_PAGE_SIZE = 25;
const MAX_PAGE_SIZE = 100;
export const PageQuery = z.object({
  page: z.coerce.number().int().min(1).default(1).meta({ description: "Which page, from 1." }),
  pageSize: z.coerce.number().int().min(1).max(MAX_PAGE_SIZE).default(DEFAULT_PAGE_SIZE).meta({ description: `How many to a page, up to ${MAX_PAGE_SIZE}.` }),
});
export const pageOf = <T extends z.ZodType>(item: T) => z.object({ items: z.array(item), total: z.number().int(), page: z.number().int(), pageSize: z.number().int() });

/** One or more of `values`, comma-separated, for a filter that matches what has any of them. */
export const anyOf = (values: readonly string[]) => z.string().refine((s) => s.split(",").every((v) => values.includes(v)), `One or more of ${values.join(", ")}, comma-separated.`);
