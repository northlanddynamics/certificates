// The audit log's search as web/src/lib keeps it in the address and turns it into the API's filters.
import { describe, expect, test } from "bun:test";
import { auditFiltersOf, auditSearchOf, targetTypeLabel } from "../../web/src/lib/audit-search";

const now = new Date("2026-10-24T12:00:00.000Z");

describe("the audit log's search", () => {
  test("keeps what it knows from the address, and drops what is malformed", () => {
    expect(auditSearchOf({ q: " team. ", types: "team,member", range: "7d", other: "x" })).toEqual({ q: "team.", types: ["team", "member"], range: "7d" });
    expect(auditSearchOf({ q: "", types: "Team;drop", range: "1y", from: "2026-01-01T00:00:00Z" })).toEqual({});
    expect(auditSearchOf({ range: "custom", from: "2026-10-01T00:00:00.000Z", to: "not a time" })).toEqual({ range: "custom", from: "2026-10-01T00:00:00.000Z" });
  });

  test("a quick range counts back from now; a custom one is as given; none is all time", () => {
    expect(auditFiltersOf({ range: "24h" }, now)).toEqual({ from: "2026-10-23T12:00:00.000Z" });
    expect(auditFiltersOf({ range: "30d" }, now)).toEqual({ from: "2026-09-24T12:00:00.000Z" });
    expect(auditFiltersOf({ range: "custom", from: "2026-10-01T00:00:00.000Z", to: "2026-10-02T00:00:00.000Z" }, now)).toEqual({ from: "2026-10-01T00:00:00.000Z", to: "2026-10-02T00:00:00.000Z" });
    expect(auditFiltersOf({ q: "admin@", types: ["team", "member"] }, now)).toEqual({ q: "admin@", targetType: "team,member" });
    expect(auditFiltersOf({}, now)).toEqual({});
  });

  test("names target types as people read them", () => {
    expect(targetTypeLabel("managed_certificate")).toBe("Managed certificate");
  });
});
