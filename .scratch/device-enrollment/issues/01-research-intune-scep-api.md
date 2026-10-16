# 01: Research: Intune's SCEP API contract and revocation mechanism

**What to build:** A research note (`docs/research/` or beside the spec) that pins down, from Microsoft's `Intune-Resource-Access` repository and "Use APIs to add third-party CAs for SCEP to Intune", exactly what the Intune Enrollment Validator must do: the endpoints and how they are discovered, the Entra app's auth flow and scopes, the validate request and its answers, the success and failure notification payloads, and how Intune asks a third-party CA to revoke a device's certificate (its revocation request API and how it is polled). It also confirms which key transport padding Windows, iOS/macOS and Android SCEP clients use.

**Blocked by:** None (can start immediately)

**Status:** done

- [x] The note cites primary sources for each fact and gives example payloads.
- [x] It says whether anything contradicts `spec.md` (validator seam, revocation feed, PKCS#1 v1.5 support), and if so the spec is updated in the same change.

## Comments

Done: `docs/research/intune-scep-api.md`. `learn.microsoft.com` was unreachable from the research environment, so the Microsoft doc facts (Entra permission names, the 60-minute revocation cool-down) come from search excerpts and are flagged in the note for re-checking in tickets 04 and 05. Windows padding is observed (OAEP); iOS/macOS (PKCS#1 v1.5) is inferred and Android is not established, which the spec covers by accepting both. The spec is updated: ts-scep replaces pkijs, the Intune validator sends only the CSR, the device ID comes from the CSR's SAN, revocation is an hourly pull, and single DES and SHA-1 requests are accepted.
