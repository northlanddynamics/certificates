// How forwarded Audit Events leave the platform: posted to a webhook as JSON, one event to a request, or written to a
// syslog receiver over TLS as RFC 5424 messages, octet-counted (RFC 5425), each carrying the event's JSON.
import { hostname } from "node:os";
import { isIP } from "node:net";
import { connect, rootCertificates } from "node:tls";

export type AuditDestination =
  | { kind: "webhook"; url: string; authorization?: string }
  | { kind: "syslog"; host: string; port: number };

export interface AuditTransport {
  /**
   * Sends `events` to `destination` in order and resolves to how many it delivered: all of them, unless it failed partway,
   * when `error` says why. A failure is never thrown.
   */
  deliver(destination: AuditDestination, events: Record<string, unknown>[]): Promise<{ delivered: number; error?: string }>;
}

/**
 * Captures what would be sent instead of sending it. Used by tests: `failing` makes every delivery fail before its first
 * event, and `failingAfter` makes the next delivery fail after taking that many.
 */
export class CapturingAuditTransport implements AuditTransport {
  readonly sent: { destination: AuditDestination; event: any }[] = [];
  failing = false;
  failingAfter: number | null = null;
  async deliver(destination: AuditDestination, events: Record<string, unknown>[]) {
    if (this.failing) return { delivered: 0, error: "the receiver answered 503" };
    const taken = events.slice(0, this.failingAfter ?? events.length);
    const failed = this.failingAfter !== null && taken.length < events.length;
    this.failingAfter = null;
    for (const event of taken) this.sent.push({ destination, event });
    return failed ? { delivered: taken.length, error: "the receiver answered 503" } : { delivered: taken.length };
  }
}

/** Facility 13 (log audit), severity 6 (informational). */
const SYSLOG_PRI = 13 * 8 + 6;
const APP_NAME = "certificate-platform";
/** How long a syslog connection that has been written and ended waits for the receiver to close it, or fail it, before it counts as delivered. */
const SYSLOG_CLOSE_GRACE_MS = 2_000;

/** One RFC 5424 message carrying `event` as its MSG, framed by its length in octets (RFC 5425). */
export function syslogFrame(event: Record<string, unknown>, host: string): string {
  const time = typeof event.occurredAt === "string" ? event.occurredAt : new Date().toISOString();
  const message = `<${SYSLOG_PRI}>1 ${time} ${host || "-"} ${APP_NAME} - audit - ${JSON.stringify(event)}`;
  return `${Buffer.byteLength(message)} ${message}`;
}

export interface AuditTransportOptions {
  /** How long one webhook request, or one syslog connection, may take. */
  timeoutMs?: number;
  /** Roots a syslog receiver's certificate may chain to, besides the system's; for tests. */
  syslogCa?: string[];
  /** The HOSTNAME syslog messages carry; this host's name unless given. */
  syslogHostname?: string;
}

const describe = (err: unknown) => (err instanceof Error ? err.message : String(err));

export function createAuditTransport({ timeoutMs = 10_000, syslogCa, syslogHostname = hostname() }: AuditTransportOptions = {}): AuditTransport {
  async function webhook(destination: Extract<AuditDestination, { kind: "webhook" }>, events: Record<string, unknown>[]) {
    let delivered = 0;
    for (const event of events) {
      try {
        const res = await fetch(destination.url, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "user-agent": APP_NAME,
            ...(destination.authorization && { authorization: destination.authorization }),
          },
          body: JSON.stringify(event),
          signal: AbortSignal.timeout(timeoutMs),
          redirect: "manual",
        });
        // The answer's body says nothing that matters; cancelling it frees the connection.
        await res.body?.cancel();
        if (res.status < 200 || res.status >= 300) return { delivered, error: `the webhook answered ${res.status}` };
      } catch (err) {
        return { delivered, error: describe(err) };
      }
      delivered++;
    }
    return { delivered };
  }

  /**
   * Writes every frame on one connection, ends it and counts them delivered once the receiver closes it in turn, or, as
   * receivers need not, once it has stayed open a moment without failing. A connection that fails delivers none of them.
   */
  function syslog(destination: Extract<AuditDestination, { kind: "syslog" }>, events: Record<string, unknown>[]) {
    return new Promise<{ delivered: number; error?: string }>((resolve) => {
      const socket = connect({
        host: destination.host,
        port: destination.port,
        // SNI names a host, never an address.
        ...(isIP(destination.host) === 0 && { servername: destination.host }),
        ...(syslogCa && { ca: [...rootCertificates, ...syslogCa] }),
      });
      let written = false;
      let settled = false;
      const settle = (outcome: { delivered: number; error?: string }) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        socket.destroy();
        resolve(outcome);
      };
      let timer = setTimeout(() => settle({ delivered: 0, error: `the syslog receiver did not answer within ${timeoutMs} ms` }), timeoutMs);
      socket.on("error", (err) => settle({ delivered: 0, error: describe(err) }));
      socket.once("close", () => settle(written ? { delivered: events.length } : { delivered: 0, error: "the syslog receiver closed the connection" }));
      // What the receiver says back, if anything, is not syslog's concern; reading it lets its close be seen.
      socket.resume();
      socket.once("secureConnect", () => {
        socket.end(events.map((e) => syslogFrame(e, syslogHostname)).join(""), () => {
          written = true;
          clearTimeout(timer);
          timer = setTimeout(() => settle({ delivered: events.length }), SYSLOG_CLOSE_GRACE_MS);
        });
      });
    });
  }

  return {
    deliver: (destination, events) => (destination.kind === "webhook" ? webhook(destination, events) : syslog(destination, events)),
  };
}
