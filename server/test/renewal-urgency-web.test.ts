// Whether a Managed Certificate's page offers Renew now first, as web/src/lib works it out: only when its latest Issuance
// failed or it is inside its renewal window; otherwise Download is first and Renew now asks before renewing early.
import { describe, expect, test } from "bun:test";
import { expiryTone, renewalUrgent, renewalWindowOpens } from "../../web/src/lib/renewal-urgency";

const DAY = 86_400_000;
const now = new Date("2026-10-24T12:00:00Z");
const at = (days: number) => new Date(now.getTime() + days * DAY).toISOString();

type Renewal = Parameters<typeof renewalUrgent>[0];
const healthy = (changes: Partial<Renewal["renewal"]> = {}, rest: Partial<Renewal> = {}): Renewal => ({
  renewal: { policy: { mode: "automatic", daysBeforeExpiry: 30 }, dueAt: at(59), dueBecause: "policy", ari: null, failing: null, blocked: null, ...changes },
  issuance: { status: "succeeded" } as Renewal["issuance"],
  currentCertificate: { notAfter: at(89) } as Renewal["currentCertificate"],
  ...rest,
});

describe("renewing first", () => {
  test("not for a fresh Certificate far from its window", () => {
    expect(renewalUrgent(healthy(), now)).toBe(false);
  });

  test("once its window has opened", () => {
    expect(renewalUrgent(healthy({ dueAt: at(-1) }), now)).toBe(true);
    expect(renewalUrgent(healthy({ dueAt: now.toISOString() }), now)).toBe(true);
  });

  test("when its latest Issuance failed, or Renewal is failing", () => {
    expect(renewalUrgent(healthy({}, { issuance: { status: "failed" } as Renewal["issuance"] }), now)).toBe(true);
    const failing = { failures: 1, lastFailure: { code: "x", message: "x", at: at(-1) }, nextAttemptAt: null };
    expect(renewalUrgent(healthy({ failing }), now)).toBe(true);
  });

  test("a manual one's window is its policy's days before it ends", () => {
    const manual = { policy: { mode: "manual" as const, daysBeforeExpiry: 30 }, dueAt: null };
    expect(renewalWindowOpens(healthy(manual))?.toISOString()).toBe(at(59));
    expect(renewalUrgent(healthy(manual, { currentCertificate: { notAfter: at(20) } as Renewal["currentCertificate"] }), now)).toBe(true);
  });

  test("never for one with no Certificate and no failure", () => {
    expect(renewalUrgent(healthy({ dueAt: null }, { currentCertificate: null, issuance: null }), now)).toBe(false);
  });
});

describe("how near its end it is", () => {
  test("well while its window is closed", () => {
    expect(expiryTone(healthy(), now)).toBeNull();
  });

  test("a warning once its window has opened, and at fault once it has ended or been revoked", () => {
    expect(expiryTone(healthy({ dueAt: at(-1) }), now)).toBe("warning");
    expect(expiryTone(healthy({}, { currentCertificate: { notAfter: at(-1) } as Renewal["currentCertificate"] }), now)).toBe("danger");
    expect(expiryTone(healthy({}, { currentCertificate: { notAfter: at(89), revocation: { reason: "keyCompromise" } } as unknown as Renewal["currentCertificate"] }), now)).toBe("danger");
  });

  test("nothing with no Certificate", () => {
    expect(expiryTone(healthy({ dueAt: null }, { currentCertificate: null }), now)).toBeNull();
  });
});
