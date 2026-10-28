// What the ADCS CAs page says of a CA and its templates (web/src/lib/adcs-ca.ts). It decides nothing: the server refuses an
// Agent or a config string it cannot take, and says which templates are available.
import { describe, expect, test } from "bun:test";
import { assignableAgents, ekuLabel, isConfigString, templatePurposes, unavailableReason } from "../../web/src/lib/adcs-ca";
import type { Agent } from "../../web/src/lib/api";

const agent = (id: string, os: Agent["os"], status: Agent["status"]) => ({ id, hostName: id, os, status }) as Agent;

describe("the ADCS CAs page", () => {
  test("a config string is a host, a backslash and a CA name", () => {
    expect(isConfigString("ca01.corp.example\\Corp Issuing CA")).toBe(true);
    expect(isConfigString(" ca01\\Corp ")).toBe(true);
    for (const text of ["ca01.corp.example", "\\Corp", "ca01\\", "a\\b\\c", ""]) expect(isConfigString(text)).toBe(false);
  });

  test("a template is for TLS with Server Authentication, for devices with Client Authentication, and for both with both", () => {
    expect(templatePurposes({ extendedKeyUsages: ["1.3.6.1.5.5.7.3.1"] })).toEqual(["TLS"]);
    expect(templatePurposes({ extendedKeyUsages: ["1.3.6.1.5.5.7.3.2"] })).toEqual(["Devices"]);
    expect(templatePurposes({ extendedKeyUsages: ["1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.1"] })).toEqual(["TLS", "Devices"]);
    expect(templatePurposes({ extendedKeyUsages: ["1.3.6.1.5.5.7.3.3"] })).toEqual([]);
    expect([ekuLabel("1.3.6.1.5.5.7.3.1"), ekuLabel("1.2.3.4")]).toEqual(["Server Authentication", "1.2.3.4"]);
  });

  test("an unavailable template says why", () => {
    const usable = { published: true, enrollable: true, subjectFromRequest: true };
    expect(unavailableReason(usable)).toBeNull();
    expect(unavailableReason({ ...usable, published: false })).toBe("The CA does not publish it.");
    expect(unavailableReason({ ...usable, enrollable: false })).toBe("The Agents' account may not enroll on it.");
    expect(unavailableReason({ ...usable, subjectFromRequest: false })).toBe("It builds the subject from Active Directory, not from the request.");
  });

  test("only Windows Agents that are not revoked are offered, besides those already assigned", () => {
    const agents = [agent("win", "windows", "online"), agent("win-off", "windows", "offline"), agent("lin", "linux", "online"), agent("win-gone", "windows", "revoked")];
    expect(assignableAgents(agents, []).map((a) => a.id)).toEqual(["win", "win-off"]);
    expect(assignableAgents(agents, ["win-gone"]).map((a) => a.id)).toEqual(["win", "win-off", "win-gone"]);
  });
});
