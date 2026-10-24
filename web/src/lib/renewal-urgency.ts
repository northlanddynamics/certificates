// Whether renewing is what a Managed Certificate's page should offer first. Pure and free of the app's imports, so the
// server's tests can run it.
import type { ManagedCertificate } from "./api";

const DAY = 24 * 60 * 60 * 1000;

type Renewable = Pick<ManagedCertificate, "renewal" | "issuance" | "currentCertificate">;

/**
 * When its renewal window opens: when the scheduler renews it, or for one it does not (a manual one), its policy's days
 * before its current Certificate ends; none with no Certificate.
 */
export function renewalWindowOpens(m: Renewable): Date | null {
  if (m.renewal.dueAt) return new Date(m.renewal.dueAt);
  if (!m.currentCertificate) return null;
  return new Date(new Date(m.currentCertificate.notAfter).getTime() - m.renewal.policy.daysBeforeExpiry * DAY);
}

/** Whether renewing is the thing to do now: its latest Issuance failed, or it is inside its renewal window. */
export function renewalUrgent(m: Renewable, now: Date): boolean {
  if (m.renewal.failing || m.issuance?.status === "failed") return true;
  const opens = renewalWindowOpens(m);
  return opens !== null && opens <= now;
}
