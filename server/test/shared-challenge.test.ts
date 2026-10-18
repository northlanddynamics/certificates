// A profile's Shared Challenge through its own interface (shared-challenge.ts): what is issued, what a PKCSReq's
// challengePassword is checked against at each moment, and how rotation, retirement and expiry change that. A Shared
// Challenge Enrollment Profile is created through the API to hold one; checks are of what the module answers, the
// profile as it is stored, and the Audit Events. Enrolling with it over SCEP is shared-challenge-enrollment.test.ts.
import { afterAll, beforeAll, beforeEach, expect, test } from "bun:test";
import { eq } from "drizzle-orm";
import { enrollmentProfile } from "../src/platform/db/schema";
import { createSharedChallenges, type SharedChallenges } from "../src/enrollment/shared-challenge";
import { PASSWORD, createHarness, type Harness } from "./support/harness";

let h: Harness;
let org: { orgId: string; cookie: string };
let now: Date;
let shared: SharedChallenges;

const DAY_MS = 86_400_000;
const START = Date.parse("2026-01-01T00:00:00Z");
const admin = { id: "", email: "admin@acme.test" };

/** Moves the clock the module reads and the one its changes are recorded at, which are the same clock in the app. */
function setNow(at: number) {
  now = new Date(at);
  h.setNow(now);
}

beforeAll(async () => {
  h = await createHarness();
});
beforeEach(async () => {
  await h.reset();
  const operator = await h.createOperator("op@platform.test", PASSWORD);
  org = await h.createOrgWithAdmin(operator, "acme", "admin@acme.test");
  now = new Date(START);
  shared = createSharedChallenges({ db: h.db, unitOfWork: h.unitOfWork, clock: () => now });
  admin.id = (await h.api("/api/me", { cookie: org.cookie })).body.user.id;
});
afterAll(async () => {
  await h.close();
});

/** The Shared Challenge Audit Events, in the order they were recorded. */
const auditOf = async () =>
  ((await h.api(`/api/organizations/${org.orgId}/audit-events`, { cookie: org.cookie })).body.items as { id: string; action: string; actor: any; detail: any }[])
    .filter((e) => e.action.startsWith("enrollment_profile.shared_challenge_"))
    .sort((x, y) => Number(x.id) - Number(y.id));
const stored = async (id: string) => (await h.db.select().from(enrollmentProfile).where(eq(enrollmentProfile.id, id)))[0]!;

/** A Shared Challenge Enrollment Profile, and the Shared Challenge it was created with. */
async function created() {
  const ca = await h.api(`/api/organizations/${org.orgId}/private-cas`, {
    cookie: org.cookie,
    body: { name: "Macs", subject: "CN=Acme Macs, O=Acme", keyAlgorithm: "ecdsa-p256", lifetimeYears: 5, permittedNames: { exact: [], zones: ["macs.acme"] } },
  });
  const res = await h.api(`/api/organizations/${org.orgId}/enrollment-profiles`, { cookie: org.cookie, body: { name: "Macs", issuingCaId: ca.body.issuingCas[0].id, validator: { kind: "shared_challenge" } } });
  expect(res.status).toBe(201);
  return { id: res.body.id as string, challenge: res.body.sharedChallenge as { id: string; challenge: string } };
}

const refusedAsWrong = { refusal: "the request's challengePassword is not the Enrollment Profile's Shared Challenge" };

test("issues a fresh challenge each time, of which only the hash is kept", () => {
  const one = shared.issue();
  const two = shared.issue();
  expect(one.shown.challenge).toMatch(/^[0-9a-f]{48}$/);
  expect(one.shown.challenge).not.toBe(two.shown.challenge);
  expect(one.held.sharedChallengeId).toBe(one.shown.id);
  expect(JSON.stringify(one.held)).not.toContain(one.shown.challenge);
  expect(shared.check({ ...one.held, previousSharedChallengeId: null, previousSharedChallengeHash: null, previousSharedChallengeExpiresAt: null }, one.shown.challenge)).toEqual({ id: one.shown.id });
});

test("checks the current challenge, refusing none or another", async () => {
  const { id, challenge } = await created();
  const profile = await stored(id);
  expect(shared.check(profile, challenge.challenge)).toEqual({ id: challenge.id });
  expect(shared.check(profile, undefined)).toEqual({ refusal: "the request has no challengePassword: present the Enrollment Profile's Shared Challenge" });
  expect(shared.check(profile, "not-it")).toEqual(refusedAsWrong);
});

test("a rotation keeps the old challenge as the previous, checked until it expires, and the expiry pass then records that it ended", async () => {
  const { id, challenge: old } = await created();
  const { shown } = await shared.rotate(admin, await stored(id), new Date(START + 7 * DAY_MS));
  let profile = await stored(id);
  expect(shared.check(profile, shown.challenge)).toEqual({ id: shown.id });
  expect(shared.check(profile, old.challenge)).toEqual({ id: old.id });

  setNow(START + 7 * DAY_MS);
  expect(shared.check(profile, old.challenge)).toEqual(refusedAsWrong);
  expect(await shared.expire()).toBe(1);
  expect(await shared.expire()).toBe(0);
  profile = await stored(id);
  expect(profile.previousSharedChallengeId).toBeNull();
  expect(shared.check(profile, shown.challenge)).toEqual({ id: shown.id });

  const [rotated, retired] = await auditOf();
  expect(rotated).toMatchObject({ action: "enrollment_profile.shared_challenge_rotated", actor: { email: "admin@acme.test" }, detail: { sharedChallenge: { id: shown.id }, previous: { id: old.id } } });
  expect(retired).toMatchObject({ action: "enrollment_profile.shared_challenge_retired", actor: { id: null }, detail: { sharedChallenge: { id: old.id }, expired: true } });
});

test("rotating over an expired previous challenge first records its expiry, with no actor", async () => {
  const { id } = await created();
  const first = await shared.rotate(admin, await stored(id), new Date(START + DAY_MS));
  setNow(START + 2 * DAY_MS);
  const second = await shared.rotate(admin, await stored(id), new Date(START + 3 * DAY_MS));
  const profile = await stored(id);
  expect(profile.previousSharedChallengeId).toBe(first.shown.id);
  expect(shared.check(profile, first.shown.challenge)).toEqual({ id: first.shown.id });
  expect(shared.check(profile, second.shown.challenge)).toEqual({ id: second.shown.id });
  expect((await auditOf()).map((e) => [e.action, e.actor.id === null])).toEqual([
    ["enrollment_profile.shared_challenge_rotated", false],
    ["enrollment_profile.shared_challenge_retired", true],
    ["enrollment_profile.shared_challenge_rotated", false],
  ]);
});

test("refuses to rotate while the previous challenge has not expired, or to an expiry not in the future", async () => {
  const { id } = await created();
  await expect(shared.rotate(admin, await stored(id), new Date(START))).rejects.toMatchObject({ status: 422 });
  await shared.rotate(admin, await stored(id), new Date(START + DAY_MS));
  await expect(shared.rotate(admin, await stored(id), new Date(START + 2 * DAY_MS))).rejects.toMatchObject({ status: 409 });
});

test("refuses a rotation that read the profile before another rotation", async () => {
  const { id } = await created();
  const read = await stored(id);
  const { shown } = await shared.rotate(admin, read, new Date(START + DAY_MS));
  await shared.retire(admin, await stored(id));
  await expect(shared.rotate(admin, read, new Date(START + DAY_MS))).rejects.toMatchObject({ status: 409 });
  expect((await stored(id)).sharedChallengeId).toBe(shown.id);
});

test("retiring the previous challenge refuses it at once, and there is then none to retire", async () => {
  const { id, challenge: old } = await created();
  await shared.rotate(admin, await stored(id), new Date(START + 7 * DAY_MS));
  const row = await shared.retire(admin, await stored(id));
  expect(shared.check(row, old.challenge)).toEqual(refusedAsWrong);
  await expect(shared.retire(admin, row)).rejects.toMatchObject({ status: 409 });
  expect((await auditOf()).at(-1)).toMatchObject({ action: "enrollment_profile.shared_challenge_retired", actor: { email: "admin@acme.test" }, detail: { expired: false } });
});
