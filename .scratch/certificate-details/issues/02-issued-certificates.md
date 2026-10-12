# 02: Issued certificates tab

**What to build:** The Issued certificates tab lists every Certificate of the Managed Certificate, newest first, and one can be opened to see its full facts, downloaded in a chosen format and chain, or revoked. See `spec.md`.

**Blocked by:** 01

**Status:** ready-for-agent

- [ ] A server test, written first, covers `GET …/managed-certificates/:id/certificates/:certId` returning subject names, issuer, serial, signature algorithm, chain, CA and ACME Account with its environment, and any revocation; and "not found" for a caller who may not see the Managed Certificate or for a Certificate of another one.
- [ ] The Certificate list item gains its serial.
- [ ] The tab is a table with a state badge (Current, Superseded, Expired, Revoked), issued date, valid from and until, shortened fingerprint with a copy button, and serial.
- [ ] Download is a dialog with format and chain choices (`EXPORT_FORMATS`, `EXPORT_CHAINS`) on each row, replacing the inline selects, shown only with the download permission.
- [ ] Revoke is a dialog with the RFC 5280 reason on each row, shown as the existing controls are (an Owner or an Administrator), and remains available on an archived Managed Certificate.
- [ ] Selecting a row opens a side sheet with that Certificate's full facts and chain, and its revocation record if any.
- [ ] Overview gains the current Certificate's issuer, serial, and CA and ACME Account from the same endpoint.
- [ ] A Managed Certificate with no Certificates shows "No Certificates yet".
- [ ] Checked in the browser pane with a Current, a Superseded and a Revoked Certificate.

## Comments
