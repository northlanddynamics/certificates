// The Shared Challenge kind of Enrollment Validator keeps the contract every kind keeps. It has no service: the platform
// checks the Shared Challenge before it is asked, so it allows every request that reaches it and is told outcomes
// without anything to reach.
import { enrollmentValidatorContract } from "./support/enrollment-validator-contract";
import { sharedChallenge } from "../src/enrollment/shared-challenge";

enrollmentValidatorContract("the Shared Challenge kind", () => ({ kind: sharedChallenge, settings: {}, secret: "" }));
