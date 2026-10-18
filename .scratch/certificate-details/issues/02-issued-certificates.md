# 02: Issued certificates tab

**What to build:** The Issued certificates tab lists every Certificate of the Managed Certificate, newest first, and one can be opened to see its full facts, downloaded in a chosen format and chain, or revoked. See `spec.md`.

**Blocked by:** 01

**Status:** ready-for-agent

- [x] A server test, written first, covers `GET …/managed-certificates/:id/certificates/:certId` returning subject names, issuer, serial, signature algorithm, chain, CA and ACME Account with its environment, and any revocation; and "not found" for a caller who may not see the Managed Certificate or for a Certificate of another one.
- [x] The Certificate list item gains its serial.
- [x] The tab is a table with a state badge (Current, Superseded, Expired, Revoked), issued date, valid from and until, shortened fingerprint with a copy button, and serial.
- [x] Download is a dialog with format and chain choices (`EXPORT_FORMATS`, `EXPORT_CHAINS`) on each row, replacing the inline selects, shown only with the download permission.
- [x] Revoke is a dialog with the RFC 5280 reason on each row, shown as the existing controls are (an Owner or an Administrator), and remains available on an archived Managed Certificate.
- [x] Selecting a row opens a side sheet with that Certificate's full facts and chain, and its revocation record if any.
- [x] Overview gains the current Certificate's issuer, serial, and CA and ACME Account from the same endpoint.
- [x] A Managed Certificate with no Certificates shows "No Certificates yet".
- [x] Checked in the browser pane with a Current, a Superseded and a Revoked Certificate.

## Comments

Implemented. Notes:
- `GET …/certificates/:certificateId` returns the list item's fields plus `subject`, `issuer`, `signatureAlgorithm` (such as "ECDSA with SHA-256"), `chain` (leaf and served intermediates, each with subject, issuer, serial, fingerprint and validity) and `acmeAccount: { id, environment }`, read from the stored chain (`server/src/pki/certificate-facts.ts`). Scenarios are in `server/test/certificate-facts.test.ts`.
- Visibility follows `GET …/managed-certificates/:id`: a Member of the Organization who may not see it gets 403 there and here, another Organization gets 404, and the page shows both as "not found". A Certificate of another Managed Certificate is 404.
- The Certificate list item already carried its serial; nothing changed there.
- `subject` is empty for Pebble's (and Let's Encrypt's short-lived) Certificates, which carry their names only as subject alternative names; the side sheet then shows only "Subject names".
- Revoke moved from Overview to a dialog on each row (`RevokeDialog`), hidden for a revoked Certificate; the inline `<details>` control is gone. Download per row reuses ticket 01's `DownloadDialog`.
- Overview's ACME Account shows its environment and id: the account URL is for those who may read ACME accounts only.
- Checked in Chromium against Pebble as an Owner (Current, Superseded and Revoked rows, side sheet, Download dialog, revoking the Superseded one, Overview), an Organization Administrator (archived page still offers Revoke; a Proposal shows "No Certificates yet"), an Approver (Download, no Revoke) and a Member who cannot see it ("not found").

