import { useQuery } from "@tanstack/react-query";
import { api, type AcmeCa, type AcmeCaTag } from "@/lib/api";

/** The ACME CAs the Organization can use, as the server lists them: the built-in ones first, Let's Encrypt Staging before Production. Anyone in it may read them. */
export const useAcmeCas = (orgId: string) => useQuery({ queryKey: ["acme-cas", orgId], queryFn: () => api.acmeCas(orgId) });

export const ACME_CA_TAG_LABELS: Record<AcmeCaTag, string> = { staging: "Staging", production: "Production" };

/** An ACME CA by its name, from its id; the id itself until the ACME CAs are read. */
export const acmeCaName = (acmeCas: AcmeCa[] | undefined, id: string) => acmeCas?.find((ca) => ca.id === id)?.name ?? id;

/** The ACME CA a Managed Certificate is issued from unless another is chosen: Let's Encrypt Staging, to try an Issuance there first. */
export const DEFAULT_ACME_CA_ID = "letsencrypt-staging";
