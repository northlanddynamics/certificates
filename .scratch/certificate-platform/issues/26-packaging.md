# 26: Packaging

**What to build:** The platform ships as container images that don't depend on any one cloud, and the Agent installs as a systemd service on Linux and a Windows Service on Windows, for amd64 and arm64.

**Blocked by:** 15 (Agent Registration and identity)

**Status:** ready-for-agent

- [ ] Container images for the platform are built reproducibly and run with only Postgres and a KMS configuration.
- [ ] The Agent builds as a single binary for Windows and Linux on amd64 and arm64.
- [ ] Installers or documented install steps register the Agent as a systemd service or Windows Service that survives reboots.
- [ ] The Agent reports its version, and upgrade is a manual reinstall (no self-update).
