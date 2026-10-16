import { FailInfo } from "./constants.js";
/** Base class for all errors thrown by this SDK. */
export declare class ScepError extends Error {
    constructor(message: string, options?: {
        cause?: unknown;
    });
}
/** A message could not be parsed, verified or decrypted. Carries the failInfo a server would report. */
export declare class ScepProtocolError extends ScepError {
    readonly failInfo: FailInfo;
    constructor(message: string, failInfo?: FailInfo, options?: {
        cause?: unknown;
    });
}
/** The SCEP server answered with pkiStatus FAILURE. */
export declare class ScepFailureError extends ScepError {
    readonly failInfo: FailInfo | undefined;
    readonly failInfoText: string | undefined;
    readonly transactionId: string;
    constructor(failInfo: FailInfo | undefined, failInfoText: string | undefined, transactionId: string);
}
/** The HTTP transport returned an unexpected status or content type. */
export declare class ScepHttpError extends ScepError {
    readonly status: number;
    readonly body?: Uint8Array | undefined;
    constructor(message: string, status: number, body?: Uint8Array | undefined);
}
