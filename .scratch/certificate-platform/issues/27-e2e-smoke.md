# 27: End-to-end smoke tests

**What to build:** A small set of browser-driven end-to-end tests runs the real platform, a real Agent and Pebble together to prove the two headline paths: the guided Deployment, and an Owner CSR proposal through Approval to download.

**Blocked by:** 06 (Approval), 18 (First Deployment (tracer))

**Status:** ready-for-agent

- [ ] A smoke test drives the guided Deployment in the browser and confirms a Deployment Run succeeded with the issued Certificate's fingerprint.
- [ ] A smoke test drives a Member's CSR proposal, an Approver's approval and the Owner's PEM download.
- [ ] The smoke tests run in CI against Pebble and a test DNS server.
