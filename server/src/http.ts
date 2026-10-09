import { z } from "@hono/zod-openapi";

export type ErrorStatus = 400 | 401 | 403 | 404 | 409 | 422 | 429 | 502;

export class HttpError extends Error {
  constructor(
    readonly status: ErrorStatus,
    message: string,
  ) {
    super(message);
  }
}

const UNIQUE_VIOLATION = "23505";
// Drizzle wraps driver errors; the Postgres error code is on the cause.
export const isUniqueViolation = (err: any) => (err?.cause?.code ?? err?.code) === UNIQUE_VIOLATION;

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
