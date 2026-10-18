// Writes the Agent protocol's contract to agent/contract/openapi.json (`bun run contract:export`).
import "reflect-metadata"; // @peculiar/x509 needs a Reflect polyfill loaded before it
import { Pool } from "pg";
import { createApp } from "../app";
import { agentContract, serializeContract } from "./agent-contract";
import { createLetsEncrypt } from "../issuance/acme/certificate-authority";
import { createLocalKms } from "../platform/crypto/kms";
import { ConsoleMailer } from "../platform/mailer";

// The app is only described, never run, so nothing here connects to anything.
const pool = new Pool({ connectionString: "postgres://unused" });
const { app } = createApp({
  pool,
  mailer: new ConsoleMailer(),
  clock: () => new Date(),
  baseURL: "http://localhost",
  secret: "unused-unused-unused-unused-unused",
  kms: createLocalKms(Buffer.alloc(32).toString("base64")),
  certificateAuthority: createLetsEncrypt(),
});
await Bun.write(new URL("../../../agent/contract/openapi.json", import.meta.url), serializeContract(agentContract(app)));
await pool.end();
