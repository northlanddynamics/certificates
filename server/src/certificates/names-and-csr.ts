// Whether a CSR is fit to issue the given names from: the one check every route that takes names, a CSR or both makes,
// so a Managed Certificate is never created, changed or renewed from a CSR that asks for something else.
import { z } from "@hono/zod-openapi";
import { CsrError, MAX_CSR_LENGTH, parseCsr, type KeyAlgorithm, type ParsedCsr } from "../pki/csr";
import { HttpError } from "../platform/http";
import { MAX_NAMES, normalizeNames, sameNames } from "../pki/names";

/** The request field for a list of names; `description` says whose names they are. */
export const namesField = (description: string) =>
  z.array(z.string()).min(1).max(MAX_NAMES).openapi({ description: `${description} A wildcard is \`*.\` and a name.` });

/** The request field for a CSR, bounded so that a larger body is refused before it is parsed. */
export const csrField = z.string().min(1).max(MAX_CSR_LENGTH).openapi({ description: "PEM." });

/**
 * Checks that `csr` is a CSR for a key of `keyAlgorithm` that asks for exactly `names`, and returns the names as they
 * are kept (normalised, without repeats) with what was read from the CSR. Throws an HttpError saying what is wrong:
 * 400 for names or a CSR that are not what they claim to be, 422 for ones that are but do not fit each other.
 */
export async function checkNamesAndCsr(input: { names: string[]; csr: string; keyAlgorithm: KeyAlgorithm }): Promise<{ names: string[]; csr: ParsedCsr }> {
  const normalized = normalizeNames(input.names);
  if ("invalid" in normalized) throw new HttpError(400, `"${normalized.invalid}" cannot be a name to issue for`);
  const csr = await parseCsr(input.csr).catch((err) => {
    if (err instanceof CsrError) throw new HttpError(400, err.message);
    throw err;
  });
  if (csr.keyAlgorithm !== input.keyAlgorithm) {
    throw new HttpError(422, `the CSR's key is ${csr.keyAlgorithm}, but the Managed Certificate's key algorithm is ${input.keyAlgorithm}`);
  }
  if (!sameNames(csr.names, normalized.names)) {
    throw new HttpError(422, `the CSR must ask for exactly the names (${normalized.names.join(", ")}), but asks for ${csr.names.join(", ")}`);
  }
  return { names: normalized.names, csr };
}
