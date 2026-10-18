// The kinds of audit forwarder, apart from the module that sends to them so that the schema can name them without importing it.
export const AUDIT_FORWARDER_KINDS = ["webhook", "syslog"] as const;
export type AuditForwarderKind = (typeof AUDIT_FORWARDER_KINDS)[number];
