# 01: Agents page says Agents authenticate with a certificate

**What to build:** The Agents page intro (`web/src/pages/agents.tsx:95`) says an Agent "identifies itself with a certificate of its own that it renews by itself". ADR 0006 replaced that mTLS design with a bearer credential the Agent rotates. Correct the copy.

**Blocked by:** none

**Status:** done

- [x] The intro says the Agent registers with a single-use token and then authenticates with a credential it replaces by itself, matching ADR 0006.
- [x] No other web copy mentions an Agent certificate or mTLS (grep `web/src`).
