// The local KMS (development and tests) against the signing contract every KMS keeps.
import { createLocalKms } from "../src/platform/crypto/kms";
import { kmsSigningContract } from "./support/kms-signing-contract";

kmsSigningContract("the local KMS", () => createLocalKms(Buffer.alloc(32, 7).toString("base64")));
