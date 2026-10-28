# 07: Requests pending at ADCS

**What to build:** Templates that need CA manager approval work:
- `adcs.submit` may come back pending with an ADCS request ID. The Issuance stays pending and shows "pending at ADCS".
- The platform asks an Agent to re-check with `adcs.check` on a backoff, at most every 15 minutes, until the request is issued or denied, or until 7 days after it was submitted.
- A denial fails the Issuance with ADCS's disposition message, and the 7 days running out fails it as "pending too long".

See `.scratch/adcs/spec.md` (Pending and timeouts).

**Blocked by:** 06 (TLS Managed Certificates from an ADCS CA).

**Status:** done

- [x] `adcs.submit` and `adcs.check` report `pending` with the request ID, and `adcs.check` is in the agent contract.
- [x] A pending Issuance is re-checked on the backoff, through any online assigned Agent, and completes when ADCS issues.
- [x] A denial and the 7-day timeout are distinct failure causes, shown in the UI.
- [x] `adcsCa.requestPending` and `adcsCa.requestDenied` Audit Events.
- [x] The template table and the issuer picker say which templates need CA manager approval.
- [x] Seam A tests use the ADCS double's pending and deny switches. Go: the contract test covers check, pending and denied, and Seam B covers `adcs.check`.

## Comments

- Server: `adcs_request` gains `pending` (migration 0063) with `checks`, `next_check_at` and `check_given_at`. `adcs.submit` and `adcs.check` both report `submission`: `issued` (requestId, certificate), `pending` (requestId) or `denied` (requestId, message). A pending request moves its Issuance's deadline to 7 days after `submitted_at` plus the hour's backstop.
- Backoff: `checkWaitMs` waits 1, 2, 4, 8 minutes, then every 15 ("at most every 15 minutes" read as the longest wait). Only an answer that it is still pending lengthens the wait. A check is a question, so one not answered within `submitTimeoutMs` is expired and asked of another online Agent (or the same, when none other is); unreachable on every Agent waits for the next check, and the request ends as `pending_too_long` if ADCS stays out of reach. A rejected check (ADCS has no such request) fails as `ca_rejected`.
- Failure codes `request_denied` (ADCS's message) and `pending_too_long`. Audit: `adcs_ca.request_submitted` has the disposition; `adcs_ca.request_pending` once, when ADCS first holds it (re-checks that find it still pending are not events, to keep the log readable); `adcs_ca.request_denied` with the message.
- Web: "Pending at ADCS" badge and activity line with the request ID and when it fails; the template table says "Needs CA manager approval" and the issuer picker notes it.
- Go: `Client.Check`; the fake has `HoldRequests`, `DenyRequests`, `Approve`, `Deny`, and holds templates with `ManagerApproval`. The contract's `Lab` gains `ApprovalTemplate` and a `Manager` (for a lab host, `certutil -resubmit` / `-deny`).
