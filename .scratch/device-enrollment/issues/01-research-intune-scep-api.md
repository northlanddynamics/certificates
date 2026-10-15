# 01: Research: Intune's SCEP API contract and revocation mechanism

**What to build:** A research note (`docs/research/` or beside the spec) that pins down, from Microsoft's `Intune-Resource-Access` repository and "Use APIs to add third-party CAs for SCEP to Intune", exactly what the Intune Enrollment Validator must do: the endpoints and how they are discovered, the Entra app's auth flow and scopes, the validate request and its answers, the success and failure notification payloads, and how Intune asks a third-party CA to revoke a device's certificate (its revocation request API and how it is polled). It also confirms which key transport padding Windows, iOS/macOS and Android SCEP clients use.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] The note cites primary sources for each fact and gives example payloads.
- [ ] It says whether anything contradicts `spec.md` (validator seam, revocation feed, PKCS#1 v1.5 support), and if so the spec is updated in the same change.
