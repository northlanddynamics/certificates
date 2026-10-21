import { useParams } from "@tanstack/react-router";
import { GuidePage, GuideSection, Steps } from "@/components/guide";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { can } from "@/lib/api";
import { useOrg } from "@/lib/use-org";

const FLOW = [
  { title: "Profiles pushed", body: "Your device management platform sends the device a trusted certificate profile and a SCEP profile." },
  { title: "Request", body: "The device makes a key and sends a CSR to the profile's SCEP URL, with a challenge." },
  { title: "Validator decides", body: "Intune checks its own challenge; a Shared Challenge is compared with the profile's." },
  { title: "Issued", body: "The Issuing CA signs a Device Certificate with the profile's usages and validity, and nothing else the CSR asks for." },
];

const COMPARISON: [string, string, string][] = [
  ["For", "Devices Intune manages", "Iru (formerly Kandji) and network gear, which can give no per-device challenge"],
  ["Challenge", "One per device, made and checked by Intune", "One for every device, made by the platform and shown once"],
  ["Names", "Intune vouches for them", "Bounded by the Issuing CA's permitted names and the profile's Name Rules"],
  ["Default validity", "365 days", "90 days"],
  ["Renewal", "The device enrolls again", "Renewal requests signed by the device's current Device Certificate"],
  ["Revocation", "Automatic when Intune retires, wipes or unenrolls a device", "By an Organization Administrator"],
];

const REFUSALS: [string, string][] = [
  ["A key type or size the profile does not allow", "Match the SCEP profile's key size to the profile's allowed device keys."],
  ["A DNS name outside the Issuing CA's permitted names", "Change the SCEP profile's subject alternative names, or the Issuing CA's permitted names."],
  ["A name the profile's Name Rules do not allow", "Change the SCEP profile's names, or the profile's Name Rules."],
  ["The Issuing CA no longer issues", "Point the profile at an active Issuing CA."],
  ["Intune refused the request", "Check admin consent and scep_challenge_provider on the Entra app, and that the device is managed by Intune."],
  ["Missing or wrong Shared Challenge", "Put the current one in the SCEP profile; check the previous one has not ended."],
  ["The profile is disabled", "A disabled profile refuses every request for good: create another."],
];

/**
 * How to set up device enrollment, on both sides: how a device enrolls, choosing a validator, Intune step by step from
 * Entra to Intune's profiles, the Shared Challenge and its rotation, and what a refusal means.
 */
export function EnrollmentGuidePage() {
  // Shown as a page or in the help panel over any of the Organization's pages.
  const orgId = useParams({ strict: false }).orgId ?? "";
  const org = useOrg(orgId);
  if (org && !can(org, "enrollmentProfile", "read")) return <p className="text-sm text-muted-foreground">Only Organization Administrators see the Enrollment Profiles.</p>;
  return (
    <GuidePage
      guide="enrollment-profiles"
      title="Setting up device enrollment"
      back={{ to: "/organizations/$orgId/enrollment-profiles", label: "Enrollment Profiles", orgId }}
      lede="An Enrollment Profile lets devices get client Certificates from one of your Issuing CAs over SCEP, in bulk, without Approval. You set it up here and in your device management platform; this guide covers both sides."
    >
      <GuideSection guide="enrollment-profiles" id="flow">
        <ol className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {FLOW.map((s, i) => (
            <li key={s.title} className="flex flex-col gap-1 rounded-lg border p-3">
              <span className="text-xs font-semibold text-primary">
                {i + 1} · {s.title}
              </span>
              <span>{s.body}</span>
            </li>
          ))}
        </ol>
      </GuideSection>

      <GuideSection guide="enrollment-profiles" id="choose">
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>
                  <span className="sr-only">Aspect</span>
                </TableHead>
                <TableHead>Microsoft Intune</TableHead>
                <TableHead>Shared Challenge</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {COMPARISON.map(([aspect, intune, shared]) => (
                <TableRow key={aspect}>
                  <TableCell className="font-medium">{aspect}</TableCell>
                  <TableCell className="whitespace-normal">{intune}</TableCell>
                  <TableCell className="whitespace-normal">{shared}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </GuideSection>

      <GuideSection guide="enrollment-profiles" id="intune">
        <span className="font-medium">In Microsoft Entra</span>
        <Steps>
          {[
            <>
              Register an app. Note its <strong>Application (client) ID</strong> and your <strong>Directory (tenant) ID</strong>.
            </>,
            <>
              Add two <strong>application</strong> permissions: Intune <code>scep_challenge_provider</code> and Microsoft Graph <code>Application.Read.All</code>.
            </>,
            <>
              <strong>Grant admin consent</strong> for both. Without it, every enrollment is refused.
            </>,
            <>
              Make a <strong>client secret</strong> and copy its value. The platform keeps it as a Secret and never shows it again.
            </>,
          ]}
        </Steps>
        <span className="font-medium">Here</span>
        <Steps start={5}>
          {[
            <>Create the profile with the tenant ID, app ID and secret, on an active Issuing CA. The platform then shows the values for Intune; they stay in the profile's menu under “Intune setup values”.</>,
            <>
              Use <strong>Test</strong>. It proves the platform can sign in and find Intune's services. It cannot prove <code>scep_challenge_provider</code>: only the first enrollment does.
            </>,
          ]}
        </Steps>
        <span className="font-medium">In Intune</span>
        <Steps start={7}>
          {[
            <>
              A <strong>trusted certificate profile</strong> with the CA certificate the profile offers to download: the root, or the Issuing CA.
            </>,
            <>
              A <strong>SCEP certificate profile</strong> with the profile's SCEP URL, a key size the profile allows, and the URI subject alternative name{" "}
              <code>{"IntuneDeviceId://{{DeviceId}}"}</code>, by which revocation finds the device's certificates.
            </>,
          ]}
        </Steps>
        <div className="rounded-md border p-3">
          Devices must be able to reach the profile's SCEP URL from wherever they enroll. When Intune retires, wipes or unenrolls a device, it queues the certificate for
          revocation; the platform collects that queue at most hourly, Intune's limit, and revokes what it finds. If Test says Microsoft cannot be reached, ask whoever runs
          the platform.
        </div>
      </GuideSection>

      <GuideSection guide="enrollment-profiles" id="shared">
        <p>
          Creating the profile makes its Shared Challenge and shows it <strong>once</strong>. Put it in your device management platform's SCEP profile as the challenge before
          closing the dialog: the platform keeps only its hash.
        </p>
        <span className="font-medium">Rotating it</span>
        <ol className="grid overflow-hidden rounded-lg border sm:grid-cols-3">
          <li className="flex flex-col gap-1 border-b p-3 sm:border-r sm:border-b-0">
            <strong>Rotate</strong>
            <span>Choose until when the current one keeps working. The new one is shown once.</span>
          </li>
          <li className="flex flex-col gap-1 border-b bg-muted/50 p-3 sm:border-r sm:border-b-0">
            <strong>Both work</strong>
            <span>Devices your platform has not yet reached keep enrolling with the previous one. Put the new one in the SCEP profile now.</span>
          </li>
          <li className="flex flex-col gap-1 p-3">
            <strong>Previous ends</strong>
            <span>On the day you chose, or at once with “Retire previous challenge”. Another rotation is refused until then.</span>
          </li>
        </ol>
        <p className="text-muted-foreground">Each Device Certificate records which Shared Challenge it was issued under, so its list shows when the previous one stops being used.</p>
      </GuideSection>

      <GuideSection guide="enrollment-profiles" id="refused">
        <p>
          A refused device is told only “badRequest”. The reason is in the Audit log, as an <code>enrollment.refused</code> event on the profile.
        </p>
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Cause</TableHead>
                <TableHead>Fix</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {REFUSALS.map(([cause, fix]) => (
                <TableRow key={cause}>
                  <TableCell className="whitespace-normal">{cause}</TableCell>
                  <TableCell className="whitespace-normal">{fix}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </GuideSection>
    </GuidePage>
  );
}
