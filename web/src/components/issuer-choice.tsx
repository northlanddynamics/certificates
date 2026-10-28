import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { TriangleAlertIcon } from "lucide-react";
import { useState } from "react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Field, FieldContent, FieldDescription, FieldError, FieldLabel, FieldTitle } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { AcmeCaTagBadge } from "@/components/acme-ca-tag";
import { ACME_CA_FILTERS, acmeCaChoices, type AcmeCaFilter } from "@/lib/acme-ca-choices";
import { ACME_CA_TAG_LABELS, acmeCaName, useAcmeCas } from "@/lib/acme-cas";
import { api, type AcmeCa, type IssuerRef } from "@/lib/api";
import { KEY_ALGORITHM_LABELS, NO_KEY_ALGORITHMS } from "@/lib/csr-generator";
import { commonNameOf, daysLabel, findIssuingCa, isValidityDays, permittedNamesLabel, validityLabel } from "@/lib/private-ca";
import { MANAGER_APPROVAL_NOTE, adcsTemplateTitle, adcsTlsChoices, templateKeysLabel } from "@/lib/adcs-ca";
// The server's own judgement of a key against a template, from a module that imports nothing.
import { templateKeyAlgorithms } from "../../../server/src/adcs/adcs-kinds";

/** The issuer chosen: an ACME CA by id, an Issuing CA of one of the Organization's Private CAs by id, or an ADCS CA and one of its templates by id. */
export type IssuerChoice = IssuerRef;
/** The issuer as a radio button's value, and back. */
const issuerValue = (i: IssuerChoice) => (i.kind === "acme" ? `acme:${i.acmeCaId}` : i.kind === "private_ca" ? `private_ca:${i.issuingCaId}` : `adcs:${i.adcsCaId}:${i.templateId}`);
const issuerOfValue = (value: string): IssuerChoice => {
  const [kind, ref] = value.split(/:(.*)/s) as [string, string];
  if (kind === "adcs") {
    const [adcsCaId, templateId] = ref.split(":") as [string, string];
    return { kind: "adcs", adcsCaId, templateId };
  }
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
 * The state of choosing where Certificates are issued from: an ACME CA, an active Issuing CA under an active root, or an
 * ADCS CA's template offered for TLS; for an Issuing CA a validity (empty for its default), which an ADCS template decides
 * itself. It starts from `initial` when given, and otherwise from the first that can issue, in the order they are offered;
 * none while nothing can. Anyone may list the ACME CAs, and see which the Organization has an account with; the Private CAs
 * are fetched only for whoever may read them, and the ADCS CAs only when `canReadAdcsCas` (and so only where they are
 * offered at all). `canRegisterAcmeAccounts` says whether the caller may register an account with an ACME CA that has none.
 */
export function useIssuerChoice(
  orgId: string,
  {
    canReadPrivateCas,
    canReadAdcsCas = false,
    canRegisterAcmeAccounts = false,
    initial,
  }: { canReadPrivateCas: boolean; canReadAdcsCas?: boolean; canRegisterAcmeAccounts?: boolean; initial?: { issuer: IssuerChoice; validityDays: number | null } },
) {
  const [picked, setIssuer] = useState<IssuerChoice | null>(initial?.issuer ?? null);
  const [validityDays, setValidityDays] = useState(initial?.validityDays == null ? "" : String(initial.validityDays));
  const [acmeCaFilter, setAcmeCaFilter] = useState<AcmeCaFilter>("all");
  const acmeCas = useAcmeCas(orgId);
  const privateCas = useQuery({ queryKey: ["private-cas", orgId], queryFn: () => api.privateCas(orgId), enabled: canReadPrivateCas });
  const adcsCas = useQuery({ queryKey: ["adcs-cas", orgId], queryFn: () => api.adcsCas(orgId), enabled: canReadAdcsCas });
  const keyAlgorithms = useKeyAlgorithms();
  // The ADCS CAs with the templates they offer for TLS.
  const adcsChoices = adcsTlsChoices(adcsCas.data?.items ?? []);
  // The Private CAs whose root is active, each with its active Issuing CAs: those that can issue, grouped as they are offered.
  const activeCas = (privateCas.data?.items ?? [])
    .filter((ca) => ca.status === "active")
    .map((ca) => ({ ...ca, issuingCas: ca.issuingCas.filter((i) => i.status === "active") }))
    .filter((ca) => ca.issuingCas.length > 0);
  // Decided once both lists are read, so that it does not move as they arrive.
  const known = acmeCas.data !== undefined && (!canReadPrivateCas || privateCas.data !== undefined) && (!canReadAdcsCas || adcsCas.data !== undefined);
  const readyAcmeCa = acmeCas.data?.items.find((ca) => ca.hasAccount);
  const readyIssuingCa = activeCas[0]?.issuingCas[0];
  const readyAdcs = adcsChoices[0];
  const firstReady: IssuerChoice | null = !known
    ? null
    : readyAcmeCa
      ? { kind: "acme", acmeCaId: readyAcmeCa.id }
      : readyIssuingCa
        ? { kind: "private_ca", issuingCaId: readyIssuingCa.id }
        : readyAdcs
          ? { kind: "adcs", adcsCaId: readyAdcs.ca.id, templateId: readyAdcs.templates[0]!.id }
          : null;
  const issuer = picked ?? firstReady;
  const chosenCa = issuer?.kind === "private_ca" ? findIssuingCa(activeCas, issuer.issuingCaId) : undefined;
  const chosenAdcs = issuer?.kind === "adcs" ? adcsChoices.find((c) => c.ca.id === issuer.adcsCaId) : undefined;
  const chosenTemplate = issuer?.kind === "adcs" ? chosenAdcs?.templates.find((t) => t.id === issuer.templateId) : undefined;
  // What a Managed Certificate on the chosen CA may have, as the server says; none until it has said. An ADCS template takes the classical keys it allows.
  const takes = !issuer
    ? undefined
    : issuer.kind === "private_ca"
      ? chosenCa?.certificateKeyAlgorithms
      : issuer.kind === "adcs"
        ? chosenTemplate && keyAlgorithms.data && templateKeyAlgorithms(chosenTemplate, keyAlgorithms.data.acmeKeyAlgorithms)
        : keyAlgorithms.data?.acmeKeyAlgorithms;
  // The validity chosen, in days; none for the Issuing CA's default.
  const chosenValidity = validityDays.trim() === "" ? null : Number(validityDays);
  const validityOk = !chosenCa || chosenValidity === null || isValidityDays(validityDays, chosenCa.validity.maximumDays);
  // Whether the chosen ACME CA has an account to issue through; unknown (undefined) until the ACME CAs are read.
  const registered = !issuer ? undefined : issuer.kind !== "acme" || acmeCas.data?.items.find((ca) => ca.id === issuer.acmeCaId)?.hasAccount;
  const title = !issuer
    ? undefined
    : issuer.kind === "acme"
      ? acmeCaName(acmeCas.data?.items, issuer.acmeCaId)
      : issuer.kind === "private_ca"
        ? chosenCa?.name
        : chosenAdcs && chosenTemplate && adcsTemplateTitle(chosenAdcs.ca.name, chosenTemplate);
  return {
    orgId,
    /** The issuer chosen; none while nothing that can issue has been chosen. */
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
    /** The ADCS CAs, each with the templates it offers for TLS. */
    adcsChoices,
    /** The ADCS CA and template chosen, when one is. */
    chosenAdcs: chosenAdcs && chosenTemplate && { ca: chosenAdcs.ca, template: chosenTemplate },
    /** The key algorithms the chosen CA takes; none until known. */
    keyAlgorithms: takes ?? NO_KEY_ALGORITHMS,
    chosenValidity,
    validityOk,
    registered,
    acmeCasKnown: acmeCas.data !== undefined,
    /** Whether both lists are read, and so whether no issuer means that nothing can issue. */
    known,
    canRegisterAcmeAccounts,
    /** The issuer chosen in words, for a summary. */
    title,
    /** The validity chosen in words, for a summary; none for an ACME CA, which decides its own; an ADCS template's own. */
    validityText: chosenCa
      ? chosenValidity !== null
        ? daysLabel(chosenValidity)
        : `${daysLabel(chosenCa.validity.defaultDays)} (the default)`
      : chosenTemplate
        ? `${daysLabel(chosenTemplate.validityDays)}, as the template decides`
        : null,
    /** What the API is given: the issuer, and for an Issuing CA the validity when one is chosen; none while no issuer is. */
    request: issuer && { issuer, ...(issuer.kind === "private_ca" && chosenValidity !== null && { validityDays: chosenValidity }) },
  };
}

/**
 * The radio buttons for each ACME CA, with its tag, filtered by tag, and each Issuing CA grouped by its Private CA, then
 * the validity for an Issuing CA. An ACME CA the Organization has no account with is shown, disabled. `idPrefix` keeps
 * the ids apart between forms.
 */
export function IssuerChoiceFields({ choice, idPrefix, trying }: { choice: ReturnType<typeof useIssuerChoice>; idPrefix: string; trying: string }) {
  const { orgId, issuer, setIssuer, validityDays, setValidityDays, acmeCas, acmeCaFilter, setAcmeCaFilter, activeCas, chosenCa, adcsChoices, validityOk, registered, acmeCasKnown, known, canRegisterAcmeAccounts } =
    choice;
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
      {known && !issuer && (
        <Alert className="border-warning/50 bg-warning/5">
          <TriangleAlertIcon className="text-warning" />
          <AlertTitle>Nothing can issue yet</AlertTitle>
          <AlertDescription>An ACME CA needs an ACME account, a Private CA an active Issuing CA, and an ADCS CA a template offered for TLS, before it can issue.</AlertDescription>
        </Alert>
      )}
      <RadioGroup value={issuer ? issuerValue(issuer) : ""} onValueChange={(value) => setIssuer(issuerOfValue(value))}>
        {listed.length === 0 && <p className="text-sm text-muted-foreground">No ACME CA has that tag.</p>}
        {listed.map(({ ca, disabled }) => (
          <FieldLabel key={ca.id} htmlFor={`${idPrefix}-acme-${ca.id}`}>
            <Field orientation="horizontal" data-disabled={disabled}>
              <FieldContent>
                <FieldTitle>
                  {ca.name} <AcmeCaTagBadge tag={ca.tag} />
                </FieldTitle>
                {acmeCaDescription(ca, trying) && <FieldDescription>{acmeCaDescription(ca, trying)}</FieldDescription>}
                {disabled && (
                  <FieldDescription>
                    No ACME account yet.{" "}
                    {canRegisterAcmeAccounts ? (
                      <Link to="/organizations/$orgId/acme-accounts" params={{ orgId }}>
                        Register an account
                      </Link>
                    ) : (
                      "Ask an Organization Administrator to register one."
                    )}
                  </FieldDescription>
                )}
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
        {adcsChoices.map(({ ca, templates }) => (
          <div key={ca.id} role="group" aria-labelledby={`${idPrefix}-adcs-${ca.id}`} className="flex flex-col gap-3">
            <p id={`${idPrefix}-adcs-${ca.id}`} className="pt-2 text-sm font-medium">
              ADCS CA {ca.name}
              <span className="block text-xs font-normal text-muted-foreground">The Organization's Active Directory Certificate Services CA, reached through its Agents; no DCV.</span>
              <span className="block text-xs font-normal text-muted-foreground">
                {ca.permittedNames ? `Permitted names: ${permittedNamesLabel(ca.permittedNames)}.` : "No Permitted Name Rules: Approval alone decides the names."}
              </span>
            </p>
            {templates.map((template) => (
              <FieldLabel key={template.id} htmlFor={`${idPrefix}-adcs-${ca.id}-${template.id}`}>
                <Field orientation="horizontal">
                  <FieldContent>
                    <FieldTitle>{template.displayName || template.name}</FieldTitle>
                    <FieldDescription className="font-mono text-xs">{template.name}</FieldDescription>
                    <FieldDescription>
                      Validity: {daysLabel(template.validityDays)}, as the template decides. Keys: {templateKeysLabel(template)}.
                    </FieldDescription>
                    {template.managerApproval && <FieldDescription>{MANAGER_APPROVAL_NOTE}</FieldDescription>}
                  </FieldContent>
                  <RadioGroupItem value={`adcs:${ca.id}:${template.id}`} id={`${idPrefix}-adcs-${ca.id}-${template.id}`} />
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
      {issuer?.kind === "acme" && acmeCasKnown && !registered && (
        <Alert className="border-warning/50 bg-warning/5">
          <TriangleAlertIcon className="text-warning" />
          <AlertTitle>No ACME account with {acmeCaName(acmeCas, issuer.acmeCaId)}</AlertTitle>
          <AlertDescription>
            Issuance would fail until the Organization has one.{" "}
            {canRegisterAcmeAccounts ? (
              <Link to="/organizations/$orgId/acme-accounts" params={{ orgId }} className="underline underline-offset-4">
                Register an account
              </Link>
            ) : (
              "Ask an Organization Administrator to register one."
            )}
          </AlertDescription>
        </Alert>
      )}
    </>
  );
}
