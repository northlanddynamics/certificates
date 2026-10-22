import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Field, FieldContent, FieldDescription, FieldError, FieldLabel, FieldTitle } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { AcmeCaTagBadge } from "@/components/acme-ca-tag";
import { ACME_CA_FILTERS, acmeCaChoices, type AcmeCaFilter } from "@/lib/acme-ca-choices";
import { ACME_CA_TAG_LABELS, DEFAULT_ACME_CA_ID, acmeCaName, useAcmeCas } from "@/lib/acme-cas";
import { api, type AcmeCa, type NewManagedCertificate } from "@/lib/api";
import { KEY_ALGORITHM_LABELS, NO_KEY_ALGORITHMS } from "@/lib/csr-generator";
import { commonNameOf, daysLabel, findIssuingCa, isValidityDays, permittedNamesLabel, validityLabel } from "@/lib/private-ca";

/** The issuer chosen: an ACME CA by id, or an Issuing CA of one of the Organization's Private CAs by id. */
export type IssuerChoice = NewManagedCertificate["issuer"];
/** The issuer as a radio button's value, and back. */
const issuerValue = (i: IssuerChoice) => (i.kind === "acme" ? `acme:${i.acmeCaId}` : `private_ca:${i.issuingCaId}`);
const issuerOfValue = (value: string): IssuerChoice => {
  const [kind, ref] = value.split(/:(.*)/s) as [string, string];
  return kind === "acme" ? { kind: "acme", acmeCaId: ref } : { kind: "private_ca", issuingCaId: ref };
};

/**
 * What an ACME CA is for, by its tag, `trying` naming what a staging one is for, such as "an Issuance"; nothing for an
 * untagged one. Only the built-in ones are known to be Let's Encrypt, so only theirs says who trusts their Certificates:
 * a custom one's tag is its administrator's label, which says nothing of that.
 */
const acmeCaDescription = (ca: AcmeCa, trying: string) =>
  ca.tag === "staging"
    ? ca.builtIn
      ? `A test service. Certificates are not trusted by browsers; use it to try ${trying} first.`
      : `Tagged for testing; use it to try ${trying} first.`
    : ca.tag === "production"
      ? ca.builtIn
        ? "A live service. Certificates are publicly trusted, and the CA's rate limits apply."
        : "Tagged for production use."
      : undefined;

const ACME_CA_FILTER_LABELS: Record<AcmeCaFilter, string> = { all: "Every tag", ...ACME_CA_TAG_LABELS, untagged: "Untagged" };

/** The key algorithms, and which ones each kind of CA takes, as the server says; they do not change while the app runs. */
export const useKeyAlgorithms = () => useQuery({ queryKey: ["key-algorithms"], queryFn: () => api.keyAlgorithms(), staleTime: Infinity });

/**
 * The state of choosing where Certificates are issued from: an ACME CA (Let's Encrypt Staging to begin with) or an
 * active Issuing CA under an active root, and for an Issuing CA a validity (empty for its default). Anyone may list the
 * ACME CAs, and see which the Organization has an account with; the Private CAs are fetched only for whoever may read them.
 */
export function useIssuerChoice(orgId: string, { canReadPrivateCas }: { canReadPrivateCas: boolean }) {
  const [issuer, setIssuer] = useState<IssuerChoice>({ kind: "acme", acmeCaId: DEFAULT_ACME_CA_ID });
  const [validityDays, setValidityDays] = useState("");
  const [acmeCaFilter, setAcmeCaFilter] = useState<AcmeCaFilter>("all");
  const acmeCas = useAcmeCas(orgId);
  const privateCas = useQuery({ queryKey: ["private-cas", orgId], queryFn: () => api.privateCas(orgId), enabled: canReadPrivateCas });
  const keyAlgorithms = useKeyAlgorithms();
  // The Private CAs whose root is active, each with its active Issuing CAs: those that can issue, grouped as they are offered.
  const activeCas = (privateCas.data?.items ?? [])
    .filter((ca) => ca.status === "active")
    .map((ca) => ({ ...ca, issuingCas: ca.issuingCas.filter((i) => i.status === "active") }))
    .filter((ca) => ca.issuingCas.length > 0);
  const chosenCa = issuer.kind === "private_ca" ? findIssuingCa(activeCas, issuer.issuingCaId) : undefined;
  // What a Managed Certificate on the chosen CA may have, as the server says; none until it has said.
  const takes = issuer.kind === "private_ca" ? chosenCa?.certificateKeyAlgorithms : keyAlgorithms.data?.acmeKeyAlgorithms;
  // The validity chosen, in days; none for the Issuing CA's default.
  const chosenValidity = validityDays.trim() === "" ? null : Number(validityDays);
  const validityOk = !chosenCa || chosenValidity === null || isValidityDays(validityDays, chosenCa.validity.maximumDays);
  // Whether the chosen ACME CA has an account to issue through; unknown (undefined) until the ACME CAs are read.
  const registered = issuer.kind !== "acme" || acmeCas.data?.items.find((ca) => ca.id === issuer.acmeCaId)?.hasAccount;
  const title = issuer.kind === "acme" ? acmeCaName(acmeCas.data?.items, issuer.acmeCaId) : chosenCa?.name;
  return {
    issuer,
    setIssuer,
    validityDays,
    setValidityDays,
    /** The ACME CAs, the built-in ones first; none until they are read. */
    acmeCas: acmeCas.data?.items ?? [],
    /** Which of their tags the picker lists. */
    acmeCaFilter,
    setAcmeCaFilter,
    activeCas,
    chosenCa,
    /** The key algorithms the chosen CA takes; none until known. */
    keyAlgorithms: takes ?? NO_KEY_ALGORITHMS,
    chosenValidity,
    validityOk,
    registered,
    acmeCasKnown: acmeCas.data !== undefined,
    /** The issuer chosen in words, for a summary. */
    title,
    /** The validity chosen in words, for a summary; none for an ACME CA, which decides its own. */
    validityText: chosenCa ? (chosenValidity !== null ? daysLabel(chosenValidity) : `${daysLabel(chosenCa.validity.defaultDays)} (the default)`) : null,
    /** What the API is given: the issuer, and for an Issuing CA the validity when one is chosen. */
    request: { issuer, ...(issuer.kind === "private_ca" && chosenValidity !== null && { validityDays: chosenValidity }) },
  };
}

/**
 * The radio buttons for each ACME CA, with its tag, filtered by tag, and each Issuing CA grouped by its Private CA, then
 * the validity for an Issuing CA. An ACME CA the Organization has no account with is shown, disabled. `idPrefix` keeps
 * the ids apart between forms.
 */
export function IssuerChoiceFields({ choice, idPrefix, trying }: { choice: ReturnType<typeof useIssuerChoice>; idPrefix: string; trying: string }) {
  const { issuer, setIssuer, validityDays, setValidityDays, acmeCas, acmeCaFilter, setAcmeCaFilter, activeCas, chosenCa, validityOk, registered, acmeCasKnown } = choice;
  const listed = acmeCaChoices(acmeCas, acmeCaFilter);
  return (
    <>
      <Field orientation="horizontal">
        <FieldLabel htmlFor={`${idPrefix}-acme-filter`} className="font-normal">
          ACME CAs tagged
        </FieldLabel>
        <Select value={acmeCaFilter} onValueChange={(value) => setAcmeCaFilter(value as AcmeCaFilter)}>
          <SelectTrigger id={`${idPrefix}-acme-filter`} className="w-40">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {ACME_CA_FILTERS.map((filter) => (
              <SelectItem key={filter} value={filter}>
                {ACME_CA_FILTER_LABELS[filter]}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </Field>
      <RadioGroup value={issuerValue(issuer)} onValueChange={(value) => setIssuer(issuerOfValue(value))}>
        {listed.length === 0 && <p className="text-sm text-muted-foreground">No ACME CA has that tag.</p>}
        {listed.map(({ ca, disabled }) => (
          <FieldLabel key={ca.id} htmlFor={`${idPrefix}-acme-${ca.id}`}>
            <Field orientation="horizontal" data-disabled={disabled}>
              <FieldContent>
                <FieldTitle>
                  {ca.name} <AcmeCaTagBadge tag={ca.tag} />
                </FieldTitle>
                {acmeCaDescription(ca, trying) && <FieldDescription>{acmeCaDescription(ca, trying)}</FieldDescription>}
                {disabled && <FieldDescription>No ACME account yet.</FieldDescription>}
              </FieldContent>
              <RadioGroupItem value={`acme:${ca.id}`} id={`${idPrefix}-acme-${ca.id}`} disabled={disabled} />
            </Field>
          </FieldLabel>
        ))}
        {activeCas.map((ca) => (
          <div key={ca.id} role="group" aria-labelledby={`${idPrefix}-ca-${ca.id}`} className="flex flex-col gap-3">
            <p id={`${idPrefix}-ca-${ca.id}`} className="pt-2 text-sm font-medium">
              Private CA {ca.name}
              <span className="block text-xs font-normal text-muted-foreground">The Organization's own CA. Trusted only where its root is installed; no DCV.</span>
              <span className="block text-xs font-normal text-muted-foreground">Keys: {ca.certificateKeyAlgorithms.map((alg) => KEY_ALGORITHM_LABELS[alg]).join(", ")}.</span>
            </p>
            {ca.issuingCas.map((issuing) => (
              <FieldLabel key={issuing.id} htmlFor={`${idPrefix}-issuing-${issuing.id}`}>
                <Field orientation="horizontal">
                  <FieldContent>
                    <FieldTitle>{commonNameOf(issuing.subject)}</FieldTitle>
                    <FieldDescription className="break-all font-mono text-xs">{issuing.subject}</FieldDescription>
                    <FieldDescription>Permitted names: {permittedNamesLabel(issuing.permittedNames)}.</FieldDescription>
                    <FieldDescription>Validity: {validityLabel(issuing.validity)}.</FieldDescription>
                  </FieldContent>
                  <RadioGroupItem value={`private_ca:${issuing.id}`} id={`${idPrefix}-issuing-${issuing.id}`} />
                </Field>
              </FieldLabel>
            ))}
          </div>
        ))}
      </RadioGroup>
      {chosenCa && (
        <Field data-invalid={!validityOk}>
          <FieldLabel htmlFor={`${idPrefix}-validity`}>Validity (days)</FieldLabel>
          <Input
            id={`${idPrefix}-validity`}
            type="number"
            min={1}
            max={chosenCa.validity.maximumDays}
            className="w-32"
            value={validityDays}
            placeholder={String(chosenCa.validity.defaultDays)}
            aria-invalid={!validityOk}
            onChange={(e) => setValidityDays(e.target.value)}
          />
          <FieldDescription>
            Leave empty for {chosenCa.name}'s default of {daysLabel(chosenCa.validity.defaultDays)}; at most {daysLabel(chosenCa.validity.maximumDays)}. No Certificate outlives its
            Issuing CA, so one issued near its end is shorter.
          </FieldDescription>
          {!validityOk && <FieldError>Choose a whole number of days from 1 to {chosenCa.validity.maximumDays}.</FieldError>}
        </Field>
      )}
      {issuer.kind === "acme" && acmeCasKnown && !registered && (
        <FieldError>
          The Organization has no ACME account with {acmeCaName(acmeCas, issuer.acmeCaId)} yet, so Issuance would fail. An Organization Administrator can register one under ACME accounts.
        </FieldError>
      )}
    </>
  );
}
