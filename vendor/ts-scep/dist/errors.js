import { FailInfo } from "./constants.js";
/** Base class for all errors thrown by this SDK. */
export class ScepError extends Error {
    constructor(message, options) {
        super(message, options);
        this.name = "ScepError";
    }
}
/** A message could not be parsed, verified or decrypted. Carries the failInfo a server would report. */
export class ScepProtocolError extends ScepError {
    constructor(message, failInfo = FailInfo.badRequest, options) {
        super(message, options);
        this.failInfo = failInfo;
        this.name = "ScepProtocolError";
    }
}
/** The SCEP server answered with pkiStatus FAILURE. */
export class ScepFailureError extends ScepError {
    constructor(failInfo, failInfoText, transactionId) {
        const name = failInfo !== undefined ? (FailInfo[failInfo] ?? String(failInfo)) : "unspecified";
        super(`SCEP request failed: ${name}${failInfoText ? ` (${failInfoText})` : ""}`);
        this.failInfo = failInfo;
        this.failInfoText = failInfoText;
        this.transactionId = transactionId;
        this.name = "ScepFailureError";
    }
}
/** The HTTP transport returned an unexpected status or content type. */
export class ScepHttpError extends ScepError {
    constructor(message, status, body) {
        super(message);
        this.status = status;
        this.body = body;
        this.name = "ScepHttpError";
    }
}
