# Spec: Managed Certificate details page

Status: done

## Problem Statement

A Managed Certificate's details are a row that expands inside the inventory, a stack of links and small controls: owners, name change, renewal, download, revoke, archive and history, all in one narrow column. There is no URL to send someone, no room to show what a Certificate actually is (its serial, issuer, chain, which CA issued it), no place to see why Issuance failed after a retry cleared it, and nowhere for Deployments or Subscribers to go when they arrive.

## Solution

A dedicated page per Managed Certificate at `/organizations/$orgId/certificates/$id`, replacing the inline expansion. A header and an alert strip are always visible; the body is tabs, each in the path and each calling its own API when opened. Sections that do not exist yet (Services, Notifications) are present as empty states, so the page's shape is stable as they are built.

## User Stories

1. As an Owner, I want a page for one Managed Certificate with a URL I can share or bookmark, so that I can send a colleague, or a renewal-failure email, straight to it.
2. As an Owner, I want to see what the Managed Certificate is: names, environment, key algorithm, Key Custody, the current Certificate's issuer, serial, fingerprint and validity ("N of M days left"), and the CA and ACME Account that issued it.
3. As an Owner, I want to see who owns it, including each owning Team and its members, and to add or remove Owners if I may.
4. As an Owner, I want to see its Renewal Policy, when the next Renewal is due and why (policy or the CA's renewal window), and to renew it now.
5. As an Owner, I want any current automation error, and the Approval or Name Change that is pending, shown at the top with the action that resolves it (Try again, Approve, Reject).
6. As an Owner, I want every Certificate it has had, newest first, each marked Current, Superseded, Expired or Revoked, with its dates, fingerprint and serial.
7. As an Owner, I want to open one Certificate to see its full facts and chain, download it in a chosen format and chain, and revoke it with an RFC 5280 reason.
8. As an Owner, I want to see its history, and each Issuance attempt with its time, kind and failure, so that I can tell why a failure was cleared by a retry.
9. As an Approver, I want to approve or reject a Proposal or Name Change on the page, beside the current names and Owners, without going to the queue; not the one I proposed.
10. As an Organization Administrator, I want to Archive it from a menu that asks for confirmation, and see a read-only page once it is archived, with only Download and Revoke left.
11. As a Member who cannot see a Managed Certificate, I want the same "not found" as for one that does not exist, so that I cannot learn that it exists.
12. As a user, I want Services and Notifications shown as empty sections saying they are not available yet, so that I know where Deployments and Subscribers will appear.

## Implementation Decisions

**Route.** `/organizations/$orgId/certificates/$id` is a layout; its tabs are child routes, not query parameters: the index is Overview, then `/issued`, `/activity`, `/services` and `/notifications`. An unknown slug redirects to Overview. The inventory's Names cell and the Approval queue's rows link to it. An Administrator's create from the New Managed Certificate dialog opens the new page; a Member's Proposal stays on the inventory with a confirmation and a link.

**Layout.**
- **Header:** names, status badge, environment, key algorithm; Renew now and Download (the current Certificate) as buttons; a "⋯" menu holding Archive behind the existing `confirm-dialog`.
- **Alert strip:** the current automation error (the latest failed Issuance or `renewal.failing`) with Try again beside it; a pending Proposal or Name Change with Approve and Reject for an Approver who did not propose it (Reject needs a reason, as in the queue), and "Awaiting Approval" for whoever proposed it.
- **Overview:** identity and facts (names and Name Change control, issuer, serial, fingerprint, validity, CA and ACME Account, Key Custody); Owners, each Team with its members and add/remove; Renewal (policy, `dueAt`, `dueBecause`, ARI window).
- **Issued certificates** (`/issued`): a table, one row per Certificate, newest first. Columns: state badge, issued, valid from and until, shortened fingerprint with copy, serial. Row actions: Download (a dialog with format and chain, replacing the three inline selects) and Revoke (a dialog with the reason). Selecting a row opens a side sheet with that Certificate's full facts: issuer, subject names, full fingerprint and serial, chain, CA and ACME Account, revocation record.
- **Activity** (`/activity`): the existing history, plus Issuance attempts.
- **Services** (`/services`) and **Notifications** (`/notifications`): one shared empty-state component with a muted "Not available yet" label and a sentence of what will appear there (Deployments, Agents and Endpoints; Subscribers). No link or control; shown to everyone. Filling in a tab replaces the empty state.

**States.** Skeletons shaped like the page while loading. While an Issuance runs, poll every 2 seconds as the inventory does, and the header says "Issuing…" or "Renewing…". An archived page shows a read-only banner and offers only Download and Revoke (Archive never blocks Revocation). A Proposal awaiting Approval or a rejected one shows the proposed names and proposer, or the rejection reason, on Overview, and "No Certificates yet" in Issued certificates. No Owners shows a visible "No Owners" note with the add control for those who may.

**Visibility.** "Not found" for a missing Managed Certificate, one the caller cannot see, and one in another Organization alike. The server decides what is visible and what may be done (`/api/me` permissions, `can(org, …)`); each tab calls only the endpoints the caller's permissions allow.

**Server contract.** The list stays light; endpoints are added rather than every row widened.
- `GET …/managed-certificates/:id/certificates/:certId`: subject names, issuer, serial, signature algorithm, chain, CA and ACME Account (and its environment), and any revocation. Visibility as the Managed Certificate's.
- The Certificate list item gains its serial.
- `GET …/managed-certificates/:id/issuances`: each attempt's time, kind (first issue, Renewal, Name Change), status, and failure code and message. The newest failure also feeds the alert strip.
- Renewal facts need no server work: the Managed Certificate already carries `renewal.dueAt`, `dueBecause`, `ari` and `failing`.
- Team members on Overview reuse the existing Teams API.

**Out of scope.** A raw PEM viewer (Download covers it, and the platform holds no private keys: ADR 0002). Placeholders beyond the two empty sections. A web test framework.

## Testing Decisions

Each new endpoint gets scenarios in `server/test/`, written test-first, including that a caller who may not see the Managed Certificate gets "not found". The web package has no unit tests and none is added; each web slice is checked by running the app and driving the page in the browser, across the states above. Issue 27's smoke gains one scenario: a Member's Proposal, then an Approver deciding it from the details page.
