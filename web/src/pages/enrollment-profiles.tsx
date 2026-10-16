import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "@tanstack/react-router";
import { createColumnHelper, tableFeatures, useTable } from "@tanstack/react-table";
import { MoreHorizontalIcon, PlusIcon } from "lucide-react";
import { useState, type FormEvent } from "react";
import {
  DEFAULT_DEVICE_EXTENDED_KEY_USAGES,
  DEFAULT_DEVICE_KEY_USAGES,
  DEFAULT_DEVICE_VALIDITY_DAYS,
  DEVICE_EXTENDED_KEY_USAGE_NAMES,
  DEVICE_KEY_TYPES,
  DEVICE_KEY_USAGES,
  MAX_DEVICE_VALIDITY_DAYS,
  type DeviceExtendedKeyUsage,
  type DeviceKeyType,
  type DeviceKeyUsage,
} from "../../../server/src/enrollment-profile-kinds";
import { DataTable } from "@/components/data-table/data-table";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Field, FieldDescription, FieldGroup, FieldLabel, FieldLegend, FieldSet } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { api, can, type EnrollmentProfile } from "@/lib/api";
import { daysLabel, issuingCaTitle, isValidityDays } from "@/lib/private-ca";
import { useAction } from "@/lib/use-action";

const ROUTE = "/app/organizations/$orgId/enrollment-profiles";

const EXTENDED_KEY_USAGE_LABEL: Record<DeviceExtendedKeyUsage, string> = {
  clientAuth: "Client authentication",
  serverAuth: "Server authentication",
  emailProtection: "Email protection",
  ipsecIKE: "IPsec IKE",
  smartcardLogon: "Smart card logon",
};
const KEY_USAGE_LABEL: Record<DeviceKeyUsage, string> = {
  digitalSignature: "Digital signature",
  nonRepudiation: "Non-repudiation",
  keyEncipherment: "Key encipherment",
  dataEncipherment: "Data encipherment",
  keyAgreement: "Key agreement",
};
const KEY_TYPE_LABEL: Record<DeviceKeyType, string> = { "rsa-2048": "RSA 2048", "rsa-3072": "RSA 3072", "rsa-4096": "RSA 4096" };

// The server lists every profile; an Organization has a handful.
const features = tableFeatures({});
const columnHelper = createColumnHelper<typeof features, EnrollmentProfile>();
const columns = columnHelper.columns([
  columnHelper.accessor("name", {
    header: "Name",
    cell: ({ row }) => <DeviceCertificatesLink profile={row.original} />,
  }),
  columnHelper.accessor("scepUrl", {
    header: "SCEP URL",
    cell: ({ cell }) => <span className="break-all font-mono text-xs">{cell.getValue()}</span>,
  }),
  columnHelper.display({
    id: "issues",
    header: "Issues",
    cell: ({ row }) => (
      <span className="text-sm">
        {row.original.extendedKeyUsage.map((usage) => EXTENDED_KEY_USAGE_LABEL[usage]).join(", ")} for {daysLabel(row.original.validityDays)}
      </span>
    ),
  }),
  columnHelper.display({ id: "actions", header: () => <span className="sr-only">Actions</span>, cell: ({ row }) => <ProfileActions profile={row.original} /> }),
]);
const noRows: EnrollmentProfile[] = [];

/**
 * The Organization's Enrollment Profiles: each fixes what the Device Certificates devices obtain from an Issuing CA
 * look like, and has a SCEP URL to paste into the device management platform, with the CA certificate its trusted
 * certificate profile needs.
 */
export function EnrollmentProfilesPage() {
  const { orgId } = useParams({ from: ROUTE });
  const org = useQuery({ queryKey: ["me"], queryFn: api.me, select: (me) => me.organizations.find((o) => o.id === orgId) }).data;
  const allowed = org ? can(org, "enrollmentProfile", "read") : false;
  const profiles = useQuery({ queryKey: ["enrollment-profiles", orgId], queryFn: () => api.enrollmentProfiles(orgId), enabled: allowed });
  const table = useTable({ features, columns, data: profiles.data?.items ?? noRows, getRowId: (p) => p.id });

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-xl font-semibold">Enrollment Profiles</h1>
        {org && can(org, "enrollmentProfile", "create") && <NewProfileDialog orgId={orgId} />}
      </div>
      <p className="text-sm text-muted-foreground">
        Devices enroll at a profile's SCEP URL and get a Device Certificate from its Issuing CA, with the profile's key usage, extended key usages and validity, and the
        subject and names of their own request. Paste the SCEP URL into your device management platform's SCEP profile, and give its trusted certificate profile the
        root.
      </p>
      {org && !allowed ? (
        <p className="text-sm text-muted-foreground">Only Organization Administrators see the Enrollment Profiles.</p>
      ) : (
        <div className="flex flex-col gap-4">
          <DataTable table={table} empty={profiles.isPending ? "Loading…" : "No Enrollment Profile yet."} />
          {profiles.error && <p className="text-sm text-destructive">{profiles.error.message}</p>}
        </div>
      )}
    </div>
  );
}

/** A profile's name, as the way to its Device Certificates. */
function DeviceCertificatesLink({ profile }: { profile: EnrollmentProfile }) {
  const { orgId } = useParams({ from: ROUTE });
  return (
    <Link to="/organizations/$orgId/enrollment-profiles/$id/device-certificates" params={{ orgId, id: profile.id }} className="font-medium underline-offset-4 hover:underline">
      {profile.name}
    </Link>
  );
}

/** A profile's menu: its Device Certificates, copy its SCEP URL, and download the certificates devices must trust. */
function ProfileActions({ profile }: { profile: EnrollmentProfile }) {
  const { orgId } = useParams({ from: ROUTE });
  return (
    <div className="flex justify-end">
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" size="icon-sm" aria-label={`Actions for ${profile.name}`}>
            <MoreHorizontalIcon />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-56">
          <DropdownMenuItem asChild>
            <Link to="/organizations/$orgId/enrollment-profiles/$id/device-certificates" params={{ orgId, id: profile.id }}>
              Device Certificates
            </Link>
          </DropdownMenuItem>
          <DropdownMenuItem onSelect={() => void navigator.clipboard.writeText(profile.scepUrl)}>Copy SCEP URL</DropdownMenuItem>
          <DropdownMenuItem asChild>
            <a href={api.enrollmentProfileCaCertificateUrl(orgId, profile.id, "root")} download>
              Download root certificate
            </a>
          </DropdownMenuItem>
          <DropdownMenuItem asChild>
            <a href={api.enrollmentProfileCaCertificateUrl(orgId, profile.id, "issuing")} download>
              Download Issuing CA certificate
            </a>
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  );
}

function NewProfileDialog({ orgId }: { orgId: string }) {
  const [open, setOpen] = useState(false);
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button>
          <PlusIcon />
          New profile
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>New Enrollment Profile</DialogTitle>
          <DialogDescription>The platform makes the profile's SCEP RA key, which it keeps, and has the Issuing CA sign its certificate.</DialogDescription>
        </DialogHeader>
        {/* Only mounted while open, so each opening starts from a clean form. */}
        {open && <NewProfileForm orgId={orgId} onDone={() => setOpen(false)} />}
      </DialogContent>
    </Dialog>
  );
}

/** Checkboxes for some of `values`, at least one. */
function Choices<T extends string>({ legend, id, values, labels, chosen, onChange }: { legend: string; id: string; values: readonly T[]; labels: Record<T, string>; chosen: T[]; onChange: (chosen: T[]) => void }) {
  return (
    <FieldSet>
      <FieldLegend variant="label">{legend}</FieldLegend>
      <FieldGroup className="gap-2">
        {values.map((value) => (
          <Field key={value} orientation="horizontal">
            <Checkbox
              id={`${id}-${value}`}
              checked={chosen.includes(value)}
              onCheckedChange={(on) => onChange(on === true ? values.filter((v) => v === value || chosen.includes(v)) : chosen.filter((v) => v !== value))}
            />
            <FieldLabel htmlFor={`${id}-${value}`} className="font-normal">
              {labels[value]}
            </FieldLabel>
          </Field>
        ))}
      </FieldGroup>
    </FieldSet>
  );
}

function NewProfileForm({ orgId, onDone }: { orgId: string; onDone: () => void }) {
  const privateCas = useQuery({ queryKey: ["private-cas", orgId], queryFn: () => api.privateCas(orgId) });
  const kinds = useQuery({ queryKey: ["enrollment-validator-kinds", orgId], queryFn: () => api.enrollmentValidatorKinds(orgId) });
  // Only an active Issuing CA under an active root issues.
  const issuingCas = (privateCas.data?.items ?? []).flatMap((ca) => (ca.status === "active" ? ca.issuingCas.filter((i) => i.status === "active").map((i) => ({ id: i.id, title: issuingCaTitle(ca.name, i.subject) })) : []));
  const [name, setName] = useState("");
  const [issuingCaId, setIssuingCaId] = useState("");
  const [validityDays, setValidityDays] = useState(String(DEFAULT_DEVICE_VALIDITY_DAYS));
  const [extendedKeyUsage, setExtendedKeyUsage] = useState<DeviceExtendedKeyUsage[]>(DEFAULT_DEVICE_EXTENDED_KEY_USAGES);
  const [keyUsage, setKeyUsage] = useState<DeviceKeyUsage[]>(DEFAULT_DEVICE_KEY_USAGES);
  const [allowedKeyTypes, setAllowedKeyTypes] = useState<DeviceKeyType[]>([...DEVICE_KEY_TYPES]);
  const [validatorKind, setValidatorKind] = useState("");
  const kind = validatorKind || kinds.data?.items[0]?.kind || "";
  const create = useAction(
    () => api.createEnrollmentProfile(orgId, { name: name.trim(), issuingCaId, validityDays: Number(validityDays), keyUsage, extendedKeyUsage, allowedKeyTypes, validator: { kind } }),
    ["enrollment-profiles"],
    onDone,
  );
  const validityOk = isValidityDays(validityDays, MAX_DEVICE_VALIDITY_DAYS);
  const ready = name.trim() !== "" && issuingCaId !== "" && kind !== "" && validityOk && extendedKeyUsage.length > 0 && keyUsage.length > 0 && allowedKeyTypes.length > 0;

  return (
    <form
      className="flex flex-col gap-4"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        create.mutate(undefined);
      }}
    >
      <FieldGroup>
        <Field>
          <FieldLabel htmlFor="profile-name">Name</FieldLabel>
          <Input id="profile-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Wi-Fi" />
        </Field>
        <Field>
          <FieldLabel htmlFor="profile-issuing-ca">Issuing CA</FieldLabel>
          <Select value={issuingCaId} onValueChange={setIssuingCaId}>
            <SelectTrigger id="profile-issuing-ca" className="w-full">
              <SelectValue placeholder={privateCas.isPending ? "Loading…" : issuingCas.length === 0 ? "No active Issuing CA" : "Choose an Issuing CA"} />
            </SelectTrigger>
            <SelectContent>
              {issuingCas.map((i) => (
                <SelectItem key={i.id} value={i.id}>
                  {i.title}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </Field>
        <Field>
          <FieldLabel htmlFor="profile-validator">Enrollment Validator</FieldLabel>
          {kinds.data && kinds.data.items.length === 0 ? (
            <FieldDescription>The platform runs no Enrollment Validator yet, so no profile can be created.</FieldDescription>
          ) : (
            <Select value={kind} onValueChange={setValidatorKind}>
              <SelectTrigger id="profile-validator" className="w-full">
                <SelectValue placeholder="Loading…" />
              </SelectTrigger>
              <SelectContent>
                {(kinds.data?.items ?? []).map((k) => (
                  <SelectItem key={k.kind} value={k.kind}>
                    {k.kind}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}
        </Field>
        <Field>
          <FieldLabel htmlFor="profile-validity">Validity (days)</FieldLabel>
          <Input id="profile-validity" inputMode="numeric" value={validityDays} onChange={(e) => setValidityDays(e.target.value)} aria-invalid={!validityOk} />
          <FieldDescription>Up to {daysLabel(MAX_DEVICE_VALIDITY_DAYS)}, and never past the Issuing CA's end.</FieldDescription>
        </Field>
        <Choices legend="Extended key usage" id="profile-eku" values={DEVICE_EXTENDED_KEY_USAGE_NAMES} labels={EXTENDED_KEY_USAGE_LABEL} chosen={extendedKeyUsage} onChange={setExtendedKeyUsage} />
        <Choices legend="Key usage" id="profile-ku" values={DEVICE_KEY_USAGES} labels={KEY_USAGE_LABEL} chosen={keyUsage} onChange={setKeyUsage} />
        <Choices legend="Device keys allowed" id="profile-keys" values={DEVICE_KEY_TYPES} labels={KEY_TYPE_LABEL} chosen={allowedKeyTypes} onChange={setAllowedKeyTypes} />
      </FieldGroup>
      {create.error && <p className="text-sm text-destructive">{create.error.message}</p>}
      <DialogFooter>
        <DialogClose asChild>
          <Button type="button" variant="outline">
            Cancel
          </Button>
        </DialogClose>
        <Button type="submit" disabled={!ready || create.isPending}>
          Create
        </Button>
      </DialogFooter>
    </form>
  );
}
