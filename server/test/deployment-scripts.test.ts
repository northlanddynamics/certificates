// The Deployment Script library, through the API against a real Postgres: Organization Administrators upload Bash or
// PowerShell scripts, every version is immutable and identified by the hash of its content, and nobody else may upload
// or edit (ADR 0004). Running a script on an Agent is a later ticket.
import * as acme from "acme-client";
import { randomBytes } from "node:crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import { BIND, PASSWORD, createHarness, type Harness } from "./support/harness";

let h: Harness;
let operator: string;
let acmeOrg: { orgId: string; cookie: string };
let globex: { orgId: string; cookie: string };

beforeAll(async () => {
  h = await createHarness();
});
beforeEach(async () => {
  await h.reset();
  operator = await h.createOperator("op@platform.test", PASSWORD);
  acmeOrg = await h.createOrgWithAdmin(operator, "acme", "admin@acme.test");
  globex = await h.createOrgWithAdmin(operator, "globex", "admin@globex.test");
});
afterAll(async () => {
  await h.close();
});

// SHA-256 of each script's exact bytes, worked out outside the platform (`printf '…\n' | shasum -a 256`).
const HELLO = { content: "echo hello\n", hash: "5dbad7dd0b9b122dcd9956884390f4aac4738caba8ff53498a7ab6718b176c30" };
const GOODBYE = { content: "echo goodbye\n", hash: "4a7e2cd1a0d6b7a217a47669277d05e70c338b388ad1781f9f38611e3026718f" };
const POWERSHELL = { content: "Write-Host hello\n", hash: "8689eff64689c988952a0f990f6740166500e8cb866402fca6c7c74b2116dee4" };

const scriptsOf = (org = acmeOrg) => `/api/organizations/${org.orgId}/deployment-scripts`;
const upload = (body: unknown, org = acmeOrg, cookie = org.cookie) => h.api(scriptsOf(org), { cookie, method: "POST", body });
const addVersion = (scriptId: string, content: string, org = acmeOrg, cookie = org.cookie) =>
  h.api(`${scriptsOf(org)}/${scriptId}/versions`, { cookie, method: "POST", body: { content } });
const auditOf = async (org = acmeOrg) =>
  (await h.api(`/api/organizations/${org.orgId}/audit-events`, { cookie: org.cookie })).body.items as { action: string; actor: any; target: any; detail: any }[];

/** Someone invited into the Organization in the role, signed in. */
async function join(role: string, email = `${role}@acme.test`) {
  const invited = await h.api("/api/auth/organization/invite-member", { cookie: acmeOrg.cookie, body: { email, role, organizationId: acmeOrg.orgId } });
  const cookie = await h.signUp(email, PASSWORD);
  await h.api("/api/auth/organization/accept-invitation", { cookie, body: { invitationId: invited.body.id } });
  return h.signIn(email, PASSWORD);
}

/** A Member who is the Owner of a Managed Certificate: an Owner holds no role of their own, so is a Member here. */
async function memberWhoOwnsACertificate() {
  const cookie = await join("member", "owner@acme.test");
  const names = [`t${randomBytes(5).toString("hex")}.${BIND.zone}`];
  const key = await acme.crypto.createPrivateEcdsaKey("P-256");
  const [, csr] = await acme.crypto.createCsr({ commonName: names[0], altNames: names }, key);
  const proposed = await h.api(`/api/organizations/${acmeOrg.orgId}/managed-certificates`, {
    cookie,
    body: { names, keyAlgorithm: "ecdsa-p256", csr: csr.toString(), owners: [{ type: "user", id: (await h.api("/api/me", { cookie })).body.user.id }] },
  });
  expect(proposed.status).toBe(201);
  return cookie;
}

const uploadHello = async (name = "install-cert", org = acmeOrg) => {
  const created = await upload({ name, interpreter: "bash", content: HELLO.content }, org);
  expect(created.status).toBe(201);
  return created.body as { id: string };
};

describe("uploading", () => {
  test("an Organization Administrator uploads a script, which becomes version 1 identified by its hash", async () => {
    const created = await upload({ name: "install-cert", interpreter: "bash", content: HELLO.content });

    expect(created.status).toBe(201);
    expect(created.body).toEqual({
      id: expect.any(String),
      name: "install-cert",
      interpreter: "bash",
      latestVersion: { version: 1, hash: HELLO.hash, size: 11, uploadedBy: "admin@acme.test", uploadedAt: "2026-01-01T00:00:00.000Z" },
    });
  });

  test("the upload is audited with the script's hash", async () => {
    const { id } = await uploadHello();

    const event = (await auditOf()).find((e) => e.action === "deployment_script.uploaded");
    expect(event).toMatchObject({
      action: "deployment_script.uploaded",
      actor: { id: expect.any(String), email: "admin@acme.test" },
      target: { type: "deployment_script", id },
      detail: { name: "install-cert", interpreter: "bash", version: 1, hash: HELLO.hash },
    });
  });
});

describe("versions", () => {
  test("uploading a change adds a version identified by its own hash, and the earlier one stays as it was", async () => {
    const { id } = await uploadHello();
    h.setNow(new Date("2026-01-02T00:00:00Z"));

    const added = await addVersion(id, GOODBYE.content);

    expect(added.status).toBe(201);
    expect(added.body).toEqual({
      id,
      name: "install-cert",
      interpreter: "bash",
      latestVersion: { version: 2, hash: GOODBYE.hash, size: 13, uploadedBy: "admin@acme.test", uploadedAt: "2026-01-02T00:00:00.000Z" },
    });
    expect((await h.api(`${scriptsOf()}/${id}`, { cookie: acmeOrg.cookie })).body.versions.map((v: any) => [v.version, v.hash])).toEqual([
      [2, GOODBYE.hash],
      [1, HELLO.hash],
    ]);
    expect((await auditOf()).filter((e) => e.action === "deployment_script.uploaded").map((e) => e.detail)).toEqual([
      { name: "install-cert", interpreter: "bash", version: 1, hash: HELLO.hash },
      { name: "install-cert", interpreter: "bash", version: 2, hash: GOODBYE.hash },
    ]);
  });

  test("content the script already has is refused: a hash names one version", async () => {
    const { id } = await uploadHello();
    await addVersion(id, GOODBYE.content);

    const again = await addVersion(id, HELLO.content);

    expect(again.status).toBe(409);
    expect(again.body.error).toContain("version 1");
    expect((await h.api(`${scriptsOf()}/${id}`, { cookie: acmeOrg.cookie })).body.versions).toHaveLength(2);
  });

  test("the same content may be a version of another script, as PowerShell or Bash alike", async () => {
    const bash = await uploadHello();
    const powershell = await upload({ name: "install-cert-windows", interpreter: "powershell", content: POWERSHELL.content });

    expect(powershell.status).toBe(201);
    expect(powershell.body.interpreter).toBe("powershell");
    expect((await addVersion(bash.id, POWERSHELL.content)).status).toBe(201);
  });

  test("two uploads at once are two versions, not one", async () => {
    const { id } = await uploadHello();

    const results = await Promise.all([addVersion(id, GOODBYE.content), addVersion(id, "echo again\n")]);

    expect(results.map((r) => r.status)).toEqual([201, 201]);
    expect(results.map((r) => r.body.latestVersion.version).sort()).toEqual([2, 3]);
  });
});

describe("immutability", () => {
  test("no route changes or removes a version or a script", async () => {
    const { id } = await uploadHello();
    const version = `${scriptsOf()}/${id}/versions/${HELLO.hash}`;

    for (const [method, path] of [["PUT", version], ["PATCH", version], ["DELETE", version], ["PUT", `${scriptsOf()}/${id}`], ["DELETE", `${scriptsOf()}/${id}`]]) {
      const res = await h.app.request(`http://localhost${path}`, { method, headers: { cookie: acmeOrg.cookie, "content-type": "application/json" }, body: JSON.stringify({ content: GOODBYE.content }) });
      expect([404, 405]).toContain(res.status);
    }
    expect((await h.api(version, { cookie: acmeOrg.cookie })).body.content).toBe(HELLO.content);
  });

  test("the database itself refuses to change or delete a version", async () => {
    const { id } = await uploadHello();

    await expect(h.pool.query(`update deployment_script_version set content = 'echo pwned' where script_id = $1`, [id])).rejects.toThrow(/immutable/);
    await expect(h.pool.query(`update deployment_script_version set hash = repeat('0', 64) where script_id = $1`, [id])).rejects.toThrow(/immutable/);
    await expect(h.pool.query(`delete from deployment_script_version where script_id = $1`, [id])).rejects.toThrow(/immutable/);

    const viewed = await h.api(`${scriptsOf()}/${id}/versions/${HELLO.hash}`, { cookie: acmeOrg.cookie });
    expect(viewed.body.content).toBe(HELLO.content);
  });
});

describe("viewing the library", () => {
  test("lists the scripts with their latest version, oldest first, without their content", async () => {
    const hello = await uploadHello("b-first");
    h.setNow(new Date("2026-01-01T00:01:00Z"));
    await upload({ name: "a-second", interpreter: "powershell", content: POWERSHELL.content });
    await addVersion(hello.id, GOODBYE.content);

    const listed = await h.api(scriptsOf(), { cookie: acmeOrg.cookie });

    expect(listed.status).toBe(200);
    expect(listed.body.items.map((s: any) => [s.name, s.interpreter, s.latestVersion.version, s.latestVersion.hash])).toEqual([
      ["b-first", "bash", 2, GOODBYE.hash],
      ["a-second", "powershell", 1, POWERSHELL.hash],
    ]);
    expect(JSON.stringify(listed.body)).not.toContain("echo");
  });

  test("pages the library, each page with its scripts' latest versions and the total in all", async () => {
    for (const name of ["s1", "s2", "s3"]) {
      h.setNow(new Date(`2026-01-01T00:0${name.slice(1)}:00Z`));
      const { id } = await uploadHello(name);
      if (name === "s2") await addVersion(id, GOODBYE.content);
    }

    const second = await h.api(`${scriptsOf()}?pageSize=2&page=2`, { cookie: acmeOrg.cookie });

    expect(second.status).toBe(200);
    expect(second.body).toMatchObject({ total: 3, page: 2, pageSize: 2 });
    expect(second.body.items.map((s: any) => [s.name, s.latestVersion.version])).toEqual([["s3", 1]]);
    const first = await h.api(`${scriptsOf()}?pageSize=2`, { cookie: acmeOrg.cookie });
    expect(first.body.items.map((s: any) => [s.name, s.latestVersion.version])).toEqual([["s1", 1], ["s2", 2]]);
    for (const query of ["?page=0", "?pageSize=101"]) expect((await h.api(`${scriptsOf()}${query}`, { cookie: acmeOrg.cookie })).status).toBe(400);
  });

  test("narrows the library to the scripts run by any of the interpreters asked for", async () => {
    await uploadHello("bash-script");
    await upload({ name: "powershell-script", interpreter: "powershell", content: POWERSHELL.content });
    const names = async (query: string) => {
      const listed = await h.api(`${scriptsOf()}?${query}`, { cookie: acmeOrg.cookie });
      expect(listed.status).toBe(200);
      // Uploaded at the same moment, so in no order of their own.
      return [listed.body.total, listed.body.items.map((s: any) => s.name).sort()];
    };

    expect(await names("interpreter=powershell")).toEqual([1, ["powershell-script"]]);
    expect(await names("interpreter=bash,powershell")).toEqual([2, ["bash-script", "powershell-script"]]);
    expect((await h.api(`${scriptsOf()}?interpreter=python`, { cookie: acmeOrg.cookie })).status).toBe(400);
  });

  test("a previous version stays viewable, with its content, by its hash", async () => {
    const { id } = await uploadHello();
    await addVersion(id, GOODBYE.content);

    const old = await h.api(`${scriptsOf()}/${id}/versions/${HELLO.hash}`, { cookie: acmeOrg.cookie });

    expect(old.status).toBe(200);
    expect(old.body).toEqual({ version: 1, hash: HELLO.hash, size: 11, uploadedBy: "admin@acme.test", uploadedAt: "2026-01-01T00:00:00.000Z", content: HELLO.content });
    expect((await h.api(`${scriptsOf()}/${id}/versions/${"0".repeat(64)}`, { cookie: acmeOrg.cookie })).status).toBe(404);
  });

  test("the content comes back exactly as uploaded", async () => {
    const content = "  #!/bin/bash\r\n\techo 'héllo'\r\n\n\n";
    const created = await upload({ name: "exact", interpreter: "bash", content });

    const hash = created.body.latestVersion.hash;
    const viewed = await h.api(`${scriptsOf()}/${created.body.id}/versions/${hash}`, { cookie: acmeOrg.cookie });

    expect(viewed.body.content).toBe(content);
    expect(viewed.body.size).toBe(Buffer.byteLength(content, "utf8"));
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  test("an Organization Administrator of another Organization sees and changes nothing here", async () => {
    const { id } = await uploadHello();

    expect((await h.api(scriptsOf(), { cookie: globex.cookie })).status).toBe(404);
    expect((await h.api(`${scriptsOf(acmeOrg)}/${id}`, { cookie: globex.cookie })).status).toBe(404);
    expect((await addVersion(id, GOODBYE.content, acmeOrg, globex.cookie)).status).toBe(404);
    // Through its own Organization's path, the script is not found either.
    expect((await h.api(`${scriptsOf(globex)}/${id}`, { cookie: globex.cookie })).status).toBe(404);
    expect((await addVersion(id, GOODBYE.content, globex)).status).toBe(404);
    expect((await h.api(scriptsOf(globex), { cookie: globex.cookie })).body.items).toEqual([]);
  });

  test("names are unique within an Organization only", async () => {
    await uploadHello("install-cert");

    expect((await upload({ name: "install-cert", interpreter: "bash", content: GOODBYE.content })).status).toBe(409);
    expect((await upload({ name: "install-cert", interpreter: "bash", content: HELLO.content }, globex)).status).toBe(201);
  });
});

describe("what is refused", () => {
  test.each([
    ["an interpreter that is neither Bash nor PowerShell", { name: "x", interpreter: "python", content: "print()" }],
    ["a blank name", { name: "  ", interpreter: "bash", content: HELLO.content }],
    ["empty content", { name: "x", interpreter: "bash", content: "" }],
    ["content of only whitespace", { name: "x", interpreter: "bash", content: " \n\t" }],
    ["content with a NUL character", { name: "x", interpreter: "bash", content: "echo a\u0000b" }],
    ["content over 256 KiB", { name: "x", interpreter: "bash", content: "#".repeat(256 * 1024 + 1) }],
  ])("%s", async (_what, body) => {
    expect((await upload(body)).status).toBe(400);
    expect((await h.api(scriptsOf(), { cookie: acmeOrg.cookie })).body.items).toEqual([]);
  });

  test("content of exactly 256 KiB is accepted, and the limit counts bytes", async () => {
    expect((await upload({ name: "max", interpreter: "bash", content: "#".repeat(256 * 1024) })).status).toBe(201);
    expect((await upload({ name: "bytes", interpreter: "bash", content: "é".repeat(128 * 1024 + 1) })).status).toBe(400);
  });

  test("a script id that is not one is not found", async () => {
    expect((await h.api(`${scriptsOf()}/nope`, { cookie: acmeOrg.cookie })).status).toBe(404);
    expect((await addVersion("nope", HELLO.content)).status).toBe(404);
  });

  test("signing in is required", async () => {
    expect((await h.api(scriptsOf(), {})).status).toBe(401);
    expect((await upload({ name: "x", interpreter: "bash", content: HELLO.content }, acmeOrg, "")).status).toBe(401);
  });
});

describe("who may see and upload", () => {
  test.each([
    ["a Member", () => join("member")],
    ["an Approver", () => join("approver")],
    ["an Owner of a Managed Certificate", memberWhoOwnsACertificate],
  ])("%s is refused, and nothing is uploaded or audited", async (_who, signIn) => {
    const cookie = await signIn();
    const existing = await uploadHello("existing");
    const before = (await auditOf()).length;

    expect((await upload({ name: "mine", interpreter: "bash", content: HELLO.content }, acmeOrg, cookie)).status).toBe(403);
    expect((await addVersion(existing.id, GOODBYE.content, acmeOrg, cookie)).status).toBe(403);

    expect((await h.api(scriptsOf(), { cookie: acmeOrg.cookie })).body.items.map((s: any) => s.name)).toEqual(["existing"]);
    expect((await auditOf()).length).toBe(before);
  });

  test.each([
    ["a Member", () => join("member")],
    ["an Approver", () => join("approver")],
    ["an Owner of a Managed Certificate", memberWhoOwnsACertificate],
  ])("%s may not read the library or any version of a script either", async (_who, signIn) => {
    const cookie = await signIn();
    const { id } = await uploadHello();

    for (const path of [scriptsOf(), `${scriptsOf()}/${id}`, `${scriptsOf()}/${id}/versions/${HELLO.hash}`]) {
      expect((await h.api(path, { cookie })).status).toBe(403);
    }
  });
});
