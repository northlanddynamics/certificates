# Research: Intune's SCEP API contract, revocation, and SCEP client padding

Ticket: `.scratch/device-enrollment/issues/01-research-intune-scep-api.md`. Researched 2026-10-16.

## Sources and how far to trust them

| Tag | Source | Status |
|---|---|---|
| **[IRA]** | [`microsoft/Intune-Resource-Access`](https://github.com/microsoft/Intune-Resource-Access/tree/eae184eea8f7dab417d3ac29cc3ac39b7db8cace/src/CsrValidation), `src/CsrValidation`, commit `eae184e` (2023-07-24). Microsoft's own Java and C# libraries for third-party SCEP CAs. | Read in full. **Primary**: it is the code Microsoft tells CAs to use. Paths below are relative to `src/CsrValidation/`. |
| **[MS-API]** | [Use APIs to add third-party CAs for SCEP to Intune](https://learn.microsoft.com/en-us/mem/intune/protect/scep-libraries-apis), which now lives at [APIs to onboard third party certificate authorities](https://learn.microsoft.com/en-us/intune/fundamentals/certificates/ref-scep-api). | **Not fetched**: `learn.microsoft.com` is unreachable from this environment, and the `MicrosoftDocs/memdocs` source repo is not public. The facts tagged with it come from search-engine excerpts of the page. Re-check them before ticket 04 ships. |
| **[MS-3P]** | [Use third-party CAs with SCEP in Intune](https://learn.microsoft.com/en-us/intune/fundamentals/certificates/third-party-ca-scep), [Remove SCEP or PKCS certificates](https://learn.microsoft.com/en-us/intune/device-configuration/certificates/remove-profiles) | Same as [MS-API]: excerpts only. |
| **[PKCS7]** | [`smallstep/pkcs7`](https://github.com/smallstep/pkcs7) `442a684`. Its `parse_go1.23_test.go` holds a real `PKCSReq` captured from a Windows device. | Primary for the Windows request: I decoded it with `openssl` (see below). |
| **[STEP]** | [`smallstep/certificates`](https://github.com/smallstep/certificates) `74be79c` (`scep/`, `CHANGELOG.md`) | Primary for the client quirks that step-ca works around. |
| **[MMDM]** | [`micromdm/scep`](https://github.com/micromdm/scep) `9902c1a` and its message library [`smallstep/scep`](https://github.com/smallstep/scep) `63893da` | Primary for what micromdm's `scepclient` sends. |
| **[TS-SCEP]** | [`northlanddynamics/ts-scep`](https://github.com/northlanddynamics/ts-scep) `b56eb8a` | Read, and its tests run under Bun 1.4.2: 81 pass, 15 interop tests skipped. |

## 1. Endpoint discovery

Intune's SCEP endpoints are not fixed URLs. They are discovered per tenant from the Intune service principal's published endpoints [IRA `csharp/ScepValidation/IntuneServiceLocationProvider.cs`, `java/.../IntuneClient.java` `RefreshServiceMap`]:

```
GET https://graph.microsoft.com/v1.0/servicePrincipals/appId=0000000a-0000-0000-c000-000000000000/endpoints
Authorization: Bearer <token for https://graph.microsoft.com/.default>
client-request-id: <new GUID>
```

- `0000000a-0000-0000-c000-000000000000` is the Microsoft Intune first-party app ID (`INTUNE_APP_ID` default).
- The answer is `{ "value": [ { "providerName": "<service>", "uri": "<base URL>" }, … ] }`. Build a map of `providerName` (lower-cased) to `uri`. The libraries fall back to the retired AAD Graph (`graph.windows.net`), whose answer uses `serviceName` instead. We do not need that fallback.
- The two services we use:
  - `ScepRequestValidationFEService`: validation and notifications.
  - `PkiConnectorFEService`: revocation.
- Example `uri` values, from the library's test fixtures (Microsoft's dogfood environment) [IRA `java/lib/src/test/java/Helper.java`]:
  - `https://fef.dmsua01.manage-dogfood.microsoft.com/RACerts/ScepRequestValidationFEService/Gateway/StatelessScepRequestValidationService`
  - `https://fef.dmsua01.manage-dogfood.microsoft.com/RACerts/StatelessPkiConnectorService/Gateway/StatelessPkiConnectorService`
- The map is cached. Both libraries clear it whenever a call to Intune fails at the HTTP level, because the service location may have moved, and rediscover on the next call.

## 2. Entra app, auth flow and scopes

- **Flow.** OAuth 2.0 client credentials (MSAL `ConfidentialClientApplication` with a client secret) against `https://login.microsoftonline.com/<TENANT>` [IRA `MsalClient.cs`, `MSALClientWrapper.java`].
- **Scopes.** One token per resource:
  - `https://graph.microsoft.com/.default` for discovery;
  - `https://api.manage.microsoft.com//.default` for the Intune calls. The library builds this as `intuneResourceUrl + "/.default"` with a trailing-slash URL, which gives the double slash, and that is what is sent [IRA `IntuneClient.cs`].
- **Configuration** [IRA `java/example/src/main/resources/com.microsoft.intune.props`]:
  - required: `TENANT` (the Entra tenant ID or domain), `AAD_APP_ID`, `AAD_APP_KEY` (the secret), and `PROVIDER_NAME_AND_VERSION`;
  - `PROVIDER_NAME_AND_VERSION` is a CA-chosen string sent as `callerInfo` and as a `UserAgent` header. For us it is a platform constant such as `northland-certificates/1.0`.
- **API permissions** [MS-API, excerpt]. Application permissions with admin consent:
  - Intune → `scep_challenge_provider` ("SCEP challenge validation");
  - Microsoft Graph → `Application.Read.All`, needed for the endpoint discovery above.
  - No source found names a separate permission for the revocation API. Ticket 04's connection test (below) proves only the two above, so ticket 05 must check revocation against a real tenant.

## 3. Common request shape

Every Intune call is a `POST` to `<discovered uri>/<path>` [IRA `IntuneClient.cs`, `IntuneClient.java` `PostRequest`]:

```
POST <uri>/<path>
Authorization: Bearer <Intune token>
Content-Type: application/json
client-request-id: <new GUID per call, the "activity id">
api-version: <service version>
UserAgent: <PROVIDER_NAME_AND_VERSION>   (sent by the Java library; the C# library omits it)
```

- **Service versions:**
  - `ScepRequestValidationFEService`: `2018-02-20` [IRA `IntuneScepValidator.cs`];
  - `PkiConnectorFEService`: `5019-05-05` [IRA `IntuneRevocationClient.cs`]. This is the literal default in both libraries, odd year included. Send it as-is.
- **HTTP errors.** A non-2xx status is a transport failure: retry and rediscover.
- **Application errors.** These come back in a 2xx body.

## 4. Validate request

The challenge is **not** sent separately. Intune's challenge is the PKCS#9 `challengePassword` inside the CSR, so validation sends the whole CSR [IRA `IntuneScepValidator.cs` `ValidateRequestAsync`; `java/example/.../Example.java`: `"BASE64 Encoded CSR would go here"`].

```
POST <ScepRequestValidationFEService>/ScepActions/validateRequest
api-version: 2018-02-20

{
  "request": {
    "transactionId": "252e27f890ea721a5a5790225ce6b42a02d14fbf",
    "certificateRequest": "MIIC…(base64 of the PKCS#10 DER)…",
    "callerInfo": "northland-certificates/1.0"
  }
}
```

`transactionId` is the SCEP transaction ID. The library example uses a GUID, but any string correlates validate with its notifications. We send the SCEP `transactionID` so all three calls share it.

The answer is always `{ "code": "<ErrorCode>", "errorDescription": "<text>" }`, and anything other than `"Success"` is a refusal [IRA `IntuneScepValidator.cs` `PostAsync`; unit tests in `csharp/unittests/IntuneScepValidatorTests.cs`]:

```json
{ "code": "Success", "errorDescription": "" }
{ "code": "ChallengeExpired", "errorDescription": "…" }
```

The codes [IRA `IntuneScepServiceException.cs`]:

- `Unknown`, `Success`
- CSR and challenge decoding: `CertificateRequestDecodingFailed`, `ChallengePasswordMissing`, `ChallengeDeserializationError`, `ChallengeDecryptionError`, `ChallengeDecodingError`
- Challenge timing: `ChallengeInvalidTimestamp`, `ChallengeExpired`
- Subject and SANs: `SubjectNameMissing`, `SubjectNameMismatch`, `SubjectAltNameMissing`, `SubjectAltNameMismatch`
- Key and usage: `KeyUsageMismatch`, `KeyLengthMismatch`, `EnhancedKeyUsageMissing`, `EnhancedKeyUsageMismatch`
- Keys and signatures: `AadKeyIdentifierListMissing`, `RegisteredKeyMismatch`, `SigningCertThumbprintMismatch`, `SignatureValidationFailed`
- Targeting: `ScepProfileNoLongerTargetedToTheClient`
- Bad IDs in the challenge: `BadCertificateRequestIdInChallenge`, `BadDeviceIdInChallenge`, `BadUserIdInChallenge`

Treat an unrecognised code as a refusal; the Java library maps it to `Unknown`. The code becomes the `enrollment.refused` reason. These are Intune's own checks, which is why the Intune kind vouches for names.

**What the answer does not include: any device ID.** The validate answer carries no Intune device ID. Neither does any other call in the contract. Ticket 04 can only store a device ID if the device's CSR carries one, which happens when the administrator's Intune SCEP profile puts `{{DeviceId}}` in a SAN. Intune's convention for this is a URI SAN `IntuneDeviceId://{{DeviceId}}`. **Unverified:** that convention is not in [IRA], and Intune's SCEP profile docs could not be fetched here, so ticket 04 must confirm it before relying on it.

## 5. Success and failure notifications

Success [IRA `IntuneScepValidator.cs` `SendSuccessNotificationAsync`; `Example.java`]:

```
POST <ScepRequestValidationFEService>/ScepActions/successNotification
api-version: 2018-02-20

{
  "notification": {
    "transactionId": "252e27f890ea721a5a5790225ce6b42a02d14fbf",
    "certificateRequest": "MIIC…(same base64 CSR)…",
    "certificateThumbprint": "3A1F…(SHA-1 of the certificate DER, hex)",
    "certificateSerialNumber": "5B0E…(hex)",
    "certificateExpirationDateUtc": "2027-10-16T09:30:00.0000000Z",
    "issuingCertificateAuthority": "CN=Northland Issuing CA 1,O=…",
    "callerInfo": "northland-certificates/1.0",
    "caConfiguration": null,
    "certificateAuthority": null
  }
}
```

- **Required fields:** `transactionId`, `certificateRequest`, `certificateThumbprint`, `certificateSerialNumber`, `certificateExpirationDateUtc` and `issuingCertificateAuthority`. The libraries reject an empty value for any of them.
- **Optional fields:** `caConfiguration` and `certificateAuthority`. They are ADCS-style and may be null.
- **Formats.**
  - The expiry is pinned: "web UTC time (YYYY-MM-DDThh:mm:ss.sssTZD) ISO 8601" [IRA `IntuneScepValidator.cs`, `certExpirationDate` doc comment].
  - The thumbprint and serial are free strings in the library ("Thumbprint of the certificate issued", "Serial number of the certificate issued"). Our choice is the SHA-1 thumbprint and the serial in hex, matching Windows' own certificate thumbprint and serial display; the serial must match what `downloadRevocationRequests` later returns, so use one format everywhere;
  - the Issuing CA's subject DN as `issuingCertificateAuthority`.
  - The DN matters for revocation: see section 6 on `issuerName`.

Failure [IRA `SendFailureNotificationAsync`]:

```
POST <ScepRequestValidationFEService>/ScepActions/failureNotification
api-version: 2018-02-20

{
  "notification": {
    "transactionId": "252e27f890ea721a5a5790225ce6b42a02d14fbf",
    "certificateRequest": "MIIC…",
    "hResult": 2147500037,
    "errorDescription": "Key type not allowed by the Enrollment Profile",
    "callerInfo": "northland-certificates/1.0"
  }
}
```

- `hResult` is a 32-bit Windows HRESULT, carried in a `long` [IRA `IntuneScepValidator.cs`, `hResult` doc comment: "32-bit error code", shown in the Intune console]. The examples use `0x8000FFFF` (`E_UNEXPECTED`) and `0xFFFF`. Intune shows it in its reports; no code list is defined.
- `errorDescription` is required, at most 255 characters [same doc comment].
- We should send `0x80004005` (`E_FAIL`), shown above as 2147500037, with our refusal reason as the description.
- Both notifications answer in the same `{code, errorDescription}` shape as validate.

## 6. Revocation: Intune asks, the CA polls

Intune never calls the CA. When a device is wiped, retired or unenrolled, or the Intune SCEP profile is removed from it, Intune removes the certificate from the device and **queues a revocation request** [MS-3P, excerpt: "queues them for revocation"; "revocation depends on API implementation by each third party"]. The CA downloads the queue, revokes, and reports back [IRA `IntuneRevocationClient.cs`, `csharp/revocationExample/Program.cs`].

Download:

```
POST <PkiConnectorFEService>/CertificateAuthorityRequests/downloadRevocationRequests
api-version: 5019-05-05

{ "downloadParameters": { "maxRequests": 500, "issuerName": null } }
```

- `maxRequests` must be from 1 to 500.
- `issuerName` is an optional filter.

The response:

```json
{
  "value": [
    {
      "requestContext": "opaque-id-1",
      "serialNumber": "5B0E…",
      "issuerName": "CN=Northland Issuing CA 1,O=…",
      "caConfiguration": null
    }
  ]
}
```

- `requestContext` and `serialNumber` are always present; `issuerName` and `caConfiguration` may be absent [IRA `CARequest/CARevocationRequest.cs`].
- There is **no reason and no device ID**: the platform matches on serial number and issuer.

Upload results, one per downloaded request:

```
POST <PkiConnectorFEService>/CertificateAuthorityRequests/uploadRevocationResults
api-version: 5019-05-05

{
  "results": [
    { "requestContext": "opaque-id-1", "succeeded": true,  "errorCode": "0",    "errorMessage": null },
    { "requestContext": "opaque-id-2", "succeeded": false, "errorCode": "4004", "errorMessage": "No such certificate" }
  ]
}
```

- **Answer.** `{ "value": true }`. Anything else means Intune did not record the results.
- **Error codes** [IRA `CARequestErrorCode.cs`]:
  - `0` None;
  - non-retryable: `4000` NonRetryableServiceException, `4001` DataSerializationError, `4002` ParameterDataInvalidError, `4003` CryptographyError, `4004` CertificateNotFoundError, `4005` ConflictError, `4006` NotSupportedError, `4007` PayloadTooLargeError;
  - retryable: `4100` RetryableServiceException, `4101` ServiceUnavailableException, `4102` ServiceTooBusyException, `4103` AuthenticationException.
- **Encoding.** The example shows the Java library's form, the code as a numeric string (`"4004"`, from `CARequestErrorCodes.Value`). The C# library sends the enum name instead (`"CertificateNotFoundError"`, via `StringEnumConverter` in `CARevocationResult.cs`). Both are Microsoft's, so the service presumably accepts either (an inference; confirm in ticket 05).
- **`succeeded: true`** must carry code `0` and no message.

Polling:

- **Cool-down.** Intune enforces a **60-minute cool-down** after each download [MS-API, excerpt].
- **One poll per tenant.** The queue is per tenant, and several Enrollment Profiles (and Entra apps) may share one tenant, so poll once an hour per tenant, with any of its apps, which keeps every app within the cool-down. (This note first said per Entra app; ticket 05 settled on per tenant.)
- **No `issuerName` filter.** Leave it out and match each request by serial (and `issuerName` when present) among the Organization's Device Certificates. The filter's exact string format is not documented. It is most likely the `issuingCertificateAuthority` we sent, but that is an inference.
- **Results.**
  - An already-revoked Device Certificate counts as success.
  - An unknown serial gets `4004`.
  - Only upload results once the Revocation has committed.
- **Draining.** A full page (500) means more are queued, but the cool-down means the next page is an hour away. Revocation latency is therefore up to an hour, plus however long Intune takes to queue the request.

## 7. Connection test

Neither the libraries nor the docs define a "ping" call. A meaningful `test()`:

1. Get a token for `https://graph.microsoft.com/.default`. This proves the tenant, app ID and secret.
2. Run endpoint discovery and find both service names. This proves `Application.Read.All` was consented.
3. Get a token for `https://api.manage.microsoft.com//.default`.

Do not call `validateRequest` with a dummy CSR: it would show up as a failed request in Intune's reports. Do not call `downloadRevocationRequests` either: it would start the 60-minute cool-down, and could consume queued requests that we then never answer. That leaves `scep_challenge_provider` unproven until the first real enrollment, so the test's result should say so.

## 8. Key transport padding and other client facts

| Client | Key transport | Content cipher | Signer digest | Evidence |
|---|---|---|---|---|
| Windows (MDM SCEP CSP) | **RSAES-OAEP**, with empty parameters (so SHA-1 and MGF1-SHA-1) | AES-128-CBC | **SHA-1** | Decoded from the captured Windows `PKCSReq` in [PKCS7] `parse_go1.23_test.go`. `openssl asn1parse` of the envelope shows `rsaesOaep` and `aes-128-cbc`, and the signer uses `sha1`. Its self-signed signer certificate has a **critical** authority key identifier, which broke Go 1.23's parser ([STEP] CHANGELOG 0.27.5). |
| iOS / macOS | PKCS#1 v1.5 (inference) | (not established) | (not established) | Apple publishes no client source. micromdm/scep, the SCEP server long used for Apple MDM, could only decrypt PKCS#1 v1.5 until it moved to smallstep/pkcs7 in Nov 2023 (`bdc9a8d`; the old mozilla `Decrypt` passes `nil` options, which means PKCS#1 v1.5). Apple devices enrolled against it, so they send v1.5. |
| Android | **Not established** | (not established) | (not established) | No primary source found. Covered by accepting both paddings. |
| micromdm `scepclient` (the spec's interop client) | PKCS#1 v1.5 | **single DES-CBC** | **SHA-1** | [MMDM] `smallstep/scep` `scep.go` calls `pkcs7.Encrypt` with the package defaults: `KeyEncryptionAlgorithm = rsaEncryption`, `ContentEncryptionAlgorithm = EncryptionAlgorithmDESCBC`, digest SHA-1 ([PKCS7] `encrypt.go`, `sign.go`). `cmd/scepclient` never reads `GetCACaps` to change them. |

Other client quirks found:

- **macOS GET encoding.** macOS sends `PKIOperation` by GET with `+` and `/` not percent-encoded, so `+` arrives as a space [STEP `scep/api/api.go`].
- **macOS renewal.** macOS renews with `PKCSReq` (not `RenewalReq`), but reports that the server can't renew unless `GetCACaps` lists `Renewal` [STEP `scep/authority.go`, `scep/api/api.go`]. Intune drives re-enrollment with a fresh challenge anyway.

**Runtime finding.** Bun 1.4.2's `node:crypto` refuses PKCS#1 v1.5 private decryption ("RSA_PKCS1_PADDING is no longer supported for private decryption", the Marvin-attack mitigation), and WebCrypto has no PKCS#1 v1.5 decryption at all. Raw RSA (`RSA_NO_PADDING`) does work.

ts-scep handles this ([TS-SCEP] `src/crypto.ts` `rsaPkcs1Decrypt`):

- **PKCS#1 v1.5 on Bun.** It decrypts with raw RSA and then decodes PKCS#1 v1.5 with implicit rejection, without branching on the padding (draft-irtf-cfrg-rsa-guidance). Malformed padding yields a synthetic key, so it is indistinguishable from a wrong key.
- **Single DES.** It runs single DES as 3DES with K1 = K2 = K3.
- **OAEP parameters.** It parses OAEP parameters, defaulting to SHA-1.
- **Reply padding.** It answers each request with the padding the request used.
- **Windows request.** It decoded and verified the Windows request above under Bun.
- **No CA key needed.** With an RA configured, `ScepServer` needs no CA private key, so the CA keeps signing through the KMS inside our handler.

## 9. What this changes in `spec.md`

Updated in the same change:

1. **CMS library.** `pkijs` with `@peculiar/x509` is replaced by **ts-scep**, for the reasons in section 8.
2. **The Intune validator sends only the CSR.** The challenge travels inside it. The seam's `validate(request)` still carries the CSR, challenge and transaction ID, since a static-challenge kind needs the challenge on its own.
3. **Device ID comes from the CSR.** The Intune device ID is read from the CSR's `IntuneDeviceId://` URI SAN when present, because Intune's API never returns one.
4. **Revocation is pulled.** The revocation feed is a poll, once an hour per tenant (see ticket 05 below), of `downloadRevocationRequests`, matched by serial and issuer. Results go back with `uploadRevocationResults`. The seam's "optional revocation feed" fits as written; the feed must also report each result back to the kind.
5. **Envelopes.**
   - Accept single DES-CBC content encryption besides AES and 3DES, without advertising it. Without DES the spec's own interop client, micromdm's `scepclient`, cannot enroll.
   - Accept SHA-1-signed requests, which Windows and micromdm send.
   - `GetCACaps` also advertises `Renewal` for validators that allow renewal.
6. **Validator configuration and permissions.**
   - Configuration also needs a platform-constant `PROVIDER_NAME_AND_VERSION`.
   - The Entra app needs `scep_challenge_provider` and Graph `Application.Read.All`.

**No contradiction** with: the validator seam's shape; PKCS#1 v1.5 support, which is needed (micromdm, Apple) alongside OAEP (Windows); and ADR 0007's reason for a software RA key.

## Open questions for ticket 04 / 05

Ticket 04 (2026-10-16), from search excerpts, `learn.microsoft.com` still being unreachable here:
- **Permissions: confirmed.** Microsoft's [Use third-party CAs with SCEP](https://learn.microsoft.com/en-us/intune/fundamentals/certificates/third-party-ca-scep) has the app given Intune → `scep_challenge_provider` and Microsoft Graph → `Application.Read.All` application permissions, with admin consent; vendor guides ([SecureW2](https://securew2.com/documentation/microsoft-intune/scep-ca-integration-with-microsoft-intune), [Keyfactor](https://docs.keyfactor.com/ejbca/latest/configure-intune), [AWS Private CA](https://docs.aws.amazon.com/privateca/latest/userguide/connector-for-scep-intune.html), which also asks for `User.Read`) agree.
- **`IntuneDeviceId://` URI SAN: confirmed as the convention**, though not Intune's own doing: the administrator's SCEP profile adds the URI `IntuneDeviceId://{{DeviceId}}`, which Microsoft recommends for NAC solutions to identify devices ([SCEPman](https://docs.scepman.com/certificate-management/microsoft-intune/android), [ClearPass](https://arubanetworking.hpe.com/techdocs/NAC/clearpass/integrations/unified-endpoint-management/intune/)). Some NAC vendors use other forms (Portnox: `https://intunedeviceid/{{DeviceId}}`); only `IntuneDeviceId://` (any case) is read.
- The 60-minute cool-down and any revocation permission are still ticket 05's.

Ticket 05 (2026-10-16), built against the Intune double; no real tenant was reachable from here, so nothing below has been seen from Intune itself:
- **Feed per tenant, not per app.** The queue is the tenant's, so the platform keys the feed by tenant ID: profiles of one tenant share one download, matched among all their Device Certificates, whichever Entra app each uses. That keeps the poll at most hourly for every app too.
- **`errorCode` is sent as the numeric string** (`"0"`, `"4004"`, `"4100"`), the Java library's form. A request the platform could not revoke after its tries is answered `4100` (RetryableServiceException), so that Intune may queue it again.
- **`issuerName`** is matched structurally against the Issuing CA's subject, so `CN=…,O=…` and `CN=…, O=…` both match.

Still open:

- Against a real tenant: confirm the 60-minute cool-down, whether revocation needs another permission, that the service takes `errorCode` as a numeric string, the form `issuerName` comes back in, and whether a tenant's queue is shared by its Entra apps (the platform assumes so).
- Also against a real tenant: whether Intune queues a request again after a `4100` result (the platform has forgotten it by then, so if not, that revocation is lost). Two risks of downloading without an issuer filter: two Organizations configured with one tenant each download it, the first taking (and answering `4004`, for good) the other's requests and the two together breaking the cool-down; and requests for another third-party CA in the tenant are answered `4004` too. Both need the issuer filter's form, or a tenant shared once across the platform.
- iOS/macOS padding is inferred, not observed. Both paddings are accepted, so this too is informational.
- Confirm the `issuerName` string format against a real tenant before relying on the filter.
- Android's padding: answered once a real Android device enrolls. Both paddings are accepted, so this is informational.
