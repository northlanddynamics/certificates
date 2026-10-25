import { useParams } from "@tanstack/react-router";
import { GuidePage, GuideSection, Steps } from "@/components/guide";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { can } from "@/lib/api";
import { useOrg } from "@/lib/use-org";

const FLOW = [
  { title: "The device is set up", body: "Your device management tool sends it two profiles: one to trust your CA, and one saying where to ask for a certificate (SCEP)." },
  { title: "The device asks", body: "It makes its own key and asks for a certificate, giving a password called a challenge." },
  { title: "The challenge is checked", body: "Intune checks its own challenges. A Shared Challenge is checked by the platform." },
  { title: "The certificate is issued", body: "The device gets a Device Certificate, made with the Enrollment Profile's settings." },
];

const COMPARISON: [string, string, string][] = [
  ["Best for", "Devices that Intune manages", "Other tools, such as Iru (formerly Kandji), and network gear"],
  ["Challenge", "A different one for each device, handled by Intune", "One for all devices, shown to you once"],
  ["Names on the certificate", "Intune confirms them", "Limited by the Issuing CA's and the profile's name rules"],
  ["Lasts (by default)", "365 days", "90 days"],
  ["Renewing", "The device enrolls again", "The device renews using its current certificate"],
  ["Revoking", "Automatic when Intune retires, wipes or unenrolls the device", "An Organization Administrator revokes it"],
];

const REFUSALS: [string, string][] = [
  ["The key type or size isn't allowed", "Set the SCEP profile's key size to one the Enrollment Profile allows."],
  ["A name isn't allowed by the Issuing CA", "Change the names in the SCEP profile, or the Issuing CA's permitted names."],
  ["A name isn't allowed by the profile's name rules", "Change the names in the SCEP profile, or the profile's name rules."],
  ["The Issuing CA no longer issues", "Choose an active Issuing CA for the profile."],
  ["Intune refused the request", "In Entra, check the app has admin consent for scep_challenge_provider. Check Intune manages the device."],
  ["The Shared Challenge is missing or wrong", "Put the current challenge in the SCEP profile. Check the previous one hasn't stopped working."],
  ["The profile is disabled", "A disabled profile refuses every device, for good. Create a new one."],
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
      lede="An Enrollment Profile lets your managed devices, such as laptops, phones and network gear, get their own certificates from one of your Issuing CAs automatically. Devices ask using SCEP, which most device management tools support. You set it up here and in your device management tool."
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
                  <span className="sr-only">Compared</span>
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
              Register an app. Write down its <strong>Application (client) ID</strong> and your <strong>Directory (tenant) ID</strong>.
            </>,
            <>
              Under API permissions, add two <strong>Application</strong> permissions: Intune <code>scep_challenge_provider</code> and Microsoft Graph{" "}
              <code>Application.Read.All</code>.
            </>,
            <>
              Choose <strong>Grant admin consent</strong>. Without it, every device is refused.
            </>,
            <>
              Create a <strong>client secret</strong> and copy its value. You paste it here once, and it is never shown again.
            </>,
          ]}
        </Steps>
        <span className="font-medium">Here</span>
        <Steps start={5}>
          {[
            <>Create the Enrollment Profile with the tenant ID, app ID and secret. The platform then shows the values to enter in Intune. You can find them again under “Intune setup values” in the profile's menu.</>,
            <>
              Choose <strong>Test</strong> to check the platform can connect to Intune. The first device to enroll shows whether the permissions are right.
            </>,
          ]}
        </Steps>
        <span className="font-medium">In Intune</span>
        <Steps start={7}>
          {[
            <>
              Create a <strong>Trusted certificate</strong> profile with the CA certificate you download from the Enrollment Profile.
            </>,
            <>
              Create a <strong>SCEP certificate</strong> profile with the SCEP URL, a key size the Enrollment Profile allows, and this URI subject alternative name:{" "}
              <code>{"IntuneDeviceId://{{DeviceId}}"}</code>. The platform uses it to find a device's certificates when revoking them.
            </>,
          ]}
        </Steps>
        <div className="rounded-md border p-3">
          Devices must be able to reach the SCEP URL from wherever they enroll. When Intune retires, wipes or unenrolls a device, the platform revokes its certificates within
          about an hour. If Test says it can't reach Microsoft, contact whoever runs the platform.
        </div>
      </GuideSection>

      <GuideSection guide="enrollment-profiles" id="shared">
        <p>
          When you create the profile, its Shared Challenge is shown <strong>once</strong>. Copy it into the SCEP profile in your device management tool before you close the
          window. It can't be shown again.
        </p>
        <span className="font-medium">Changing it</span>
        <ol className="grid overflow-hidden rounded-lg border sm:grid-cols-3">
          <li className="flex flex-col gap-1 border-b p-3 sm:border-r sm:border-b-0">
            <strong>Rotate</strong>
            <span>Choose how long the current one keeps working. The new one is shown once.</span>
          </li>
          <li className="flex flex-col gap-1 border-b bg-muted/50 p-3 sm:border-r sm:border-b-0">
            <strong>Both work</strong>
            <span>Put the new one in your SCEP profile now. Devices that haven't picked it up yet keep using the old one.</span>
          </li>
          <li className="flex flex-col gap-1 p-3">
            <strong>The old one stops</strong>
            <span>On the day you chose, or straight away with “Retire previous challenge”. You can't change it again until then.</span>
          </li>
        </ol>
        <p className="text-muted-foreground">Each Device Certificate shows which challenge it used, so you can see when the old one is no longer needed.</p>
      </GuideSection>

      <GuideSection guide="enrollment-profiles" id="refused">
        <p>
          A refused device only gets a general error. To see why, look in the Audit log for an <code>enrollment.refused</code> event on the profile.
        </p>
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Reason</TableHead>
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
