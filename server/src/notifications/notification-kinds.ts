// The kinds of notification channel and the events notices are sent for, apart from the module that sends them so that
// the schema can name them without importing it.
export const NOTIFICATION_CHANNEL_KINDS = ["email", "webhook"] as const;
export type NotificationChannelKind = (typeof NOTIFICATION_CHANNEL_KINDS)[number];

/** Every event a Managed Certificate's Subscribers are told of. */
export const NOTICE_EVENTS = [
  "certificate.expiring",
  "renewal.succeeded",
  "renewal.failed",
  "deployment_run.failed",
  "agent.offline",
  "approval.decided",
] as const;
export type NoticeEvent = (typeof NOTICE_EVENTS)[number];
