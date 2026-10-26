# 12: The real MS-WCCE client

**What to build:** The Windows implementation of the Agent's ADCS client. It uses MS-WCCE through the CertEnroll and CertCli COM interfaces, as the Agent's gMSA, for every method:
- discover: published templates, their facts, and whether the gMSA may enroll
- fetch the chain
- submit
- check
- revoke.

It must pass the same contract test as the fake. That test runs behind a build tag on a Windows lab host with ADCS, and someone runs it by hand before release. The Agent's install documentation covers running it as a gMSA, the Enroll right on templates, and "Issue and Manage Certificates" for revocation. See `.scratch/adcs/spec.md` (Go Agent).

**Blocked by:** 04 (Tracer), 06 (TLS Managed Certificates from an ADCS CA), 07 (Requests pending at ADCS), 08 (Revoking at ADCS).

**Status:** ready-for-human

- [ ] A Windows-only build of the ADCS client implements every interface method with MS-WCCE.
- [ ] Template discovery reads the facts the contract names, including "Supply in the request" and the gMSA's Enroll right.
- [ ] ADCS dispositions map to issued, pending and denied, and failures to `rejected` or `unreachable`, as the fake's do.
- [ ] The contract test passes against a lab ADCS behind its build tag, and the run is recorded in this ticket's Comments.
- [ ] CI builds the Agent for Windows with the real client.
- [ ] The install documentation for ADCS: gMSA, rights, and a troubleshooting section for the common DCOM and permission errors.
