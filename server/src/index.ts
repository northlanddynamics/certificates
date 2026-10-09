import { Pool } from "pg";
import { createApp } from "./app";
import { ConsoleMailer } from "./mailer";
import { runMigrations } from "./migrate";
import { bootstrapPlatformOperator } from "./operator";

const databaseUrl = process.env.DATABASE_URL;
const secret = process.env.AUTH_SECRET;
if (!databaseUrl || !secret) throw new Error("DATABASE_URL and AUTH_SECRET are required");

const pool = new Pool({ connectionString: databaseUrl });
const { app, auth, db } = createApp({
  pool,
  mailer: new ConsoleMailer(),
  clock: () => new Date(),
  baseURL: process.env.BASE_URL ?? "http://localhost:3000",
  webURL: process.env.WEB_URL,
  trustedOrigins: process.env.TRUSTED_ORIGINS?.split(",").map((o) => o.trim()).filter(Boolean),
  secret,
});
await runMigrations(pool);

if (process.env.OPERATOR_EMAIL && process.env.OPERATOR_PASSWORD) {
  await bootstrapPlatformOperator(auth, db, {
    email: process.env.OPERATOR_EMAIL,
    password: process.env.OPERATOR_PASSWORD,
    name: "Platform Operator",
  });
}

export default { port: Number(process.env.PORT ?? 3000), fetch: app.fetch };
