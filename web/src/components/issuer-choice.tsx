import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Field, FieldContent, FieldDescription, FieldError, FieldLabel, FieldTitle } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { api, type NewManagedCertificate } from "@/lib/api";
import { commonNameOf, daysLabel, findIssuingCa, isValidityDays, permittedNamesLabel, validityLabel } from "@/lib/private-ca";

type Environment = "staging" | "production";
/** The issuer chosen: an ACME environment, or an Issuing CA of one of the Organization's Private CAs by id. */
export type IssuerChoice = NewManagedCertificate["issuer"];
/** The issuer as a radio button's value, and back. */
const issuerValue = (i: IssuerChoice) => (i.kind === "acme" ? `acme:${i.environment}` : `private_ca:${i.issuingCaId}`);
const issuerOfValue = (value: string): IssuerChoice => {
  const [kind, ref] = value.split(":") as [string, string];
  return kind === "acme" ? { kind: "acme", environment: ref as Environment } : { kind: "private_ca", issuingCaId: ref };
};

/** The ACME environments, `trying` naming what staging is for, such as "an Issuance". */
const environments = (trying: string): { value: Environment; title: string; description: string }[] => [
  { value: "staging", title: "Staging", description: `The CA's test service. Certificates are not trusted by browsers; use it to try ${trying} first.` },
  { value: "production", title: "Production", description: "The CA's live service. Certificates are publicly trusted, and the CA's rate limits apply." },
];

/**
 * The state of choosing where Certificates are issued from: an ACME environment (staging to begin with) or an active
 * Issuing CA under an active root, and for an Issuing CA a validity (empty for its default). The ACME accounts and the
 * Private CAs are fetched only for whoever may read them.
 */
export function useIssuerChoice(orgId: string, { canReadAccounts, canReadPrivateCas }: { canReadAccounts: boolean; canReadPrivateCas: boolean }) {
  const [issuer, setIssuer] = useState<IssuerChoice>({ kind: "acme", environment: "staging" });
  const [validityDays, setValidityDays] = useState("");
  const accounts = useQuery({ queryKey: ["acme-accounts", orgId], queryFn: () => api.acmeAccounts(orgId), enabled: canReadAccounts });
  const privateCas = useQuery({ queryKey: ["private-cas", orgId], queryFn: () => api.privateCas(orgId), enabled: canReadPrivateCas });
  // The Private CAs whose root is active, each with its active Issuing CAs: those that can issue, grouped as they are offered.
  const activeCas = (privateCas.data?.items ?? [])
    .filter((ca) => ca.status === "active")
    .map((ca) => ({ ...ca, issuingCas: ca.issuingCas.filter((i) => i.status === "active") }))
    .filter((ca) => ca.issuingCas.length > 0);
  const chosenCa = issuer.kind === "private_ca" ? findIssuingCa(activeCas, issuer.issuingCaId) : undefined;
  // The validity chosen, in days; none for the Issuing CA's default.
  const chosenValidity = validityDays.trim() === "" ? null : Number(validityDays);
  const validityOk = !chosenCa || chosenValidity === null || isValidityDays(validityDays, chosenCa.validity.maximumDays);
  // Whether the chosen ACME environment has an account to issue through; unknown (undefined) until the accounts are read.
  const registered = issuer.kind !== "acme" || accounts.data?.items.some((a) => a.environment === issuer.environment);
  const title = issuer.kind === "acme" ? environments("").find((e) => e.value === issuer.environment)?.title : chosenCa?.name;
  return {
    issuer,
    setIssuer,
    validityDays,
    setValidityDays,
    activeCas,
    chosenCa,
    chosenValidity,
    validityOk,
    registered,
    accountsKnown: accounts.data !== undefined,
    /** The issuer chosen in words, for a summary. */
    title,
    /** The validity chosen in words, for a summary; none for an ACME CA, which decides its own. */
    validityText: chosenCa ? (chosenValidity !== null ? daysLabel(chosenValidity) : `${daysLabel(chosenCa.validity.defaultDays)} (the default)`) : null,
    /** What the API is given: the issuer, and for an Issuing CA the validity when one is chosen. */
    request: { issuer, ...(issuer.kind === "private_ca" && chosenValidity !== null && { validityDays: chosenValidity }) },
  };
}

/** The radio buttons for each ACME environment and each Issuing CA grouped by its Private CA, then the validity for an Issuing CA. `idPrefix` keeps the ids apart between forms. */
export function IssuerChoiceFields({ choice, idPrefix, trying }: { choice: ReturnType<typeof useIssuerChoice>; idPrefix: string; trying: string }) {
  const { issuer, setIssuer, validityDays, setValidityDays, activeCas, chosenCa, validityOk, registered, accountsKnown } = choice;
  return (
    <>
      <RadioGroup value={issuerValue(issuer)} onValueChange={(value) => setIssuer(issuerOfValue(value))}>
        {environments(trying).map((env) => (
          <FieldLabel key={env.value} htmlFor={`${idPrefix}-env-${env.value}`}>
            <Field orientation="horizontal">
              <FieldContent>
                <FieldTitle>{env.title}</FieldTitle>
                <FieldDescription>{env.description}</FieldDescription>
              </FieldContent>
              <RadioGroupItem value={`acme:${env.value}`} id={`${idPrefix}-env-${env.value}`} />
            </Field>
          </FieldLabel>
        ))}
        {activeCas.map((ca) => (
          <div key={ca.id} role="group" aria-labelledby={`${idPrefix}-ca-${ca.id}`} className="flex flex-col gap-3">
            <p id={`${idPrefix}-ca-${ca.id}`} className="pt-2 text-sm font-medium">
              Private CA {ca.name}
              <span className="block text-xs font-normal text-muted-foreground">The Organization's own CA. Trusted only where its root is installed; no DCV.</span>
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
      {issuer.kind === "acme" && accountsKnown && !registered && (
        <FieldError>The Organization has no {issuer.environment} ACME account yet, so Issuance would fail. An Organization Administrator can register one under ACME accounts.</FieldError>
      )}
    </>
  );
}
