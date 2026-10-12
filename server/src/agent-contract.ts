// The contract of the Agent protocol: the routes under /api/agent, as OpenAPI generated from their route schemas. The Agent
// (agent/) is built against the copy of it in agent/contract/, and the stub platform its Seam B tests run against is
// built from that copy, so a change to the protocol that is not carried over to the Agent fails a test on one side or the
// other. Regenerate the copy with `bun run contract:export`; a test (agent-contract.test.ts) fails while it is stale.
import type { OpenAPIHono } from "@hono/zod-openapi";

export function agentContract(app: OpenAPIHono) {
  const doc = app.getOpenAPI31Document({
    openapi: "3.1.0",
    info: { title: "Certificate Platform Agent protocol", version: "0.1.0" },
  });
  return {
    ...doc,
    paths: Object.fromEntries(Object.entries(doc.paths ?? {}).filter(([path]) => path.startsWith("/api/agent/"))),
  };
}

export const serializeContract = (contract: unknown) => JSON.stringify(contract, null, 2) + "\n";
