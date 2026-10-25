import { useParams } from "@tanstack/react-router";
import { CommandBlock } from "@/components/command-block";
import { GuideLink, GuidePage, GuideSection, Steps } from "@/components/guide";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { can } from "@/lib/api";
import { useOrg } from "@/lib/use-org";

const DOES: [string, string][] = [
  ["Keeps keys for Deployments", "It makes the key on its own server, gets the Certificate, and runs a Deployment Script to install it, on every renewal."],
  ["Reaches DNS inside your network", "It can make DNS changes for a DNS Provider that the platform can't reach from outside."],
];

const STATUSES: [string, string][] = [
  ["Online", "It has been in touch in the last two minutes."],
  ["Offline", "It hasn't been in touch for two minutes. Its work waits until it is back, so renewals it looks after are held up. Check its service is running and can reach the platform."],
  ["Outdated", "It is older than the latest version, shown at the top of the Agents page. Replace the program and restart the service: it stays registered."],
  ["Revoked", "It can no longer connect. To use that server again, register it with a new token."],
];

const TROUBLE: [string, string][] = [
  ["the registration token is not valid: it is unknown, used or expired", "Each token works once, for 7 days. Make a new one."],
  ["the platform URL must be https", "Use the address that starts with https://, as shown in step 2."],
  ["A TLS or certificate error", "Your network may check HTTPS traffic with its own certificate. Add --ca-file with that root certificate (PEM) to both commands."],
  ["the platform no longer accepts this Agent's credential", "The Agent was revoked, or was off for too long. Register it again with a new token."],
  ["It registers but then shows as offline", "The service isn't running, or runs as another account than the one that registered it. Run both as the same account."],
];

/** The commands for one operating system: install, register and keep running, with this platform's address filled in. */
function linuxSteps(platform: string) {
  return {
    install: `sudo install -m 0755 ./agent /usr/local/bin/certificate-agent
sudo AGENT_REGISTRATION_TOKEN=agt_... certificate-agent register --platform ${platform}`,
    service: `sudo tee /etc/systemd/system/certificate-agent.service > /dev/null <<'EOF'
[Unit]
Description=Certificate Agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/certificate-agent run
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl enable --now certificate-agent`,
  };
}

function windowsSteps(platform: string) {
  return {
    install: `New-Item -ItemType Directory -Force "C:\\Program Files\\CertificateAgent" | Out-Null
Copy-Item .\\agent.exe "C:\\Program Files\\CertificateAgent\\agent.exe"
$env:AGENT_REGISTRATION_TOKEN = "agt_..."
& "C:\\Program Files\\CertificateAgent\\agent.exe" register --platform ${platform}
icacls "$env:ProgramData\\CertificateAgent" /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F"`,
    service: `$action = New-ScheduledTaskAction -Execute "C:\\Program Files\\CertificateAgent\\agent.exe" -Argument "run"
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName "Certificate Agent" -Action $action -Trigger $trigger -Settings $settings -User "SYSTEM" -RunLevel Highest
Start-ScheduledTask -TaskName "Certificate Agent"`,
  };
}

/** How to set up an Agent: what it does, what it needs, installing and registering it on Linux and Windows, its statuses, and fixing problems. */
export function AgentGuidePage() {
  // Shown as a page or in the help panel over any of the Organization's pages.
  const orgId = useParams({ strict: false }).orgId ?? "";
  const org = useOrg(orgId);
  if (org && !can(org, "agent", "read")) return <p className="text-sm text-muted-foreground">Only Organization Administrators see the Agents.</p>;
  // The address people open the app at is the one the Agent connects to.
  const platform = window.location.origin;
  const linux = linuxSteps(platform);
  const windows = windowsSteps(platform);
  return (
    <GuidePage
      guide="agents"
      title="Setting up an Agent"
      back={{ to: "/organizations/$orgId/agents", label: "Agents", orgId }}
      lede="An Agent is a small program you install on one of your own servers. It works for the platform there: it keeps keys and installs Certificates for Deployments, and it can reach DNS inside your network. It only ever connects out to the platform, so you don't need to open any ports."
    >
      <GuideSection guide="agents" id="what">
        <div className="grid gap-3 md:grid-cols-2">
          {DOES.map(([title, body]) => (
            <div key={title} className="flex flex-col gap-1 rounded-lg border p-4">
              <span className="font-semibold">{title}</span>
              <span>{body}</span>
            </div>
          ))}
        </div>
        <p className="text-muted-foreground">One Agent can look after many Deployments. Install one on each server where Certificates need to be installed.</p>
      </GuideSection>

      <GuideSection guide="agents" id="before">
        <ul className="flex list-disc flex-col gap-1.5 pl-5">
          <li>A server running Linux, Windows or macOS, on x86-64 or ARM64.</li>
          <li>
            It can open HTTPS connections to <code>{platform}</code>.
          </li>
          <li>The Agent program for that system, which whoever runs the platform provides.</li>
          <li>Administrator (root) rights on the server.</li>
        </ul>
        <p className="text-muted-foreground">
          The Agent runs your Deployment Scripts with its own rights. Run it as an account that can do what they need, such as writing a web server's files and reloading
          it. The commands below run it as root or SYSTEM.
        </p>
      </GuideSection>

      <GuideSection guide="agents" id="install">
        <Steps>
          {[
            <>
              On the Agents page, choose <strong>Register an Agent</strong>, then <strong>Make a registration token</strong>. Copy it: it is shown once, works once, and
              expires after 7 days.
            </>,
            <>
              On the server, install the program and register it, putting your token in place of <code>agt_...</code>. Then set it up to start with the server.
            </>,
          ]}
        </Steps>
        <Tabs defaultValue="linux" className="min-w-0">
          <TabsList>
            <TabsTrigger value="linux">Linux</TabsTrigger>
            <TabsTrigger value="windows">Windows</TabsTrigger>
            <TabsTrigger value="macos">macOS</TabsTrigger>
          </TabsList>
          <TabsContent value="linux" className="mt-4 flex flex-col gap-3">
            <span className="font-medium">Install and register</span>
            <CommandBlock code={linux.install} shell="bash" label="Install and register on Linux" />
            <span className="font-medium">Start it with the server (systemd)</span>
            <CommandBlock code={linux.service} shell="bash" label="Run the Agent as a systemd service" />
          </TabsContent>
          <TabsContent value="windows" className="mt-4 flex flex-col gap-3">
            <p className="text-muted-foreground">In PowerShell, run as Administrator.</p>
            <span className="font-medium">Install and register</span>
            <CommandBlock code={windows.install} shell="powershell" label="Install and register on Windows" />
            <span className="font-medium">Start it with the server</span>
            <CommandBlock code={windows.service} shell="powershell" label="Run the Agent at startup on Windows" />
          </TabsContent>
          <TabsContent value="macos" className="mt-4 flex flex-col gap-3">
            <p>
              Install and register it as on Linux, with <code>sudo</code>. Then run <code>certificate-agent run</code> at startup with a launchd daemon in{" "}
              <code>/Library/LaunchDaemons</code>, with <code>KeepAlive</code> set.
            </p>
          </TabsContent>
        </Tabs>
        <Steps start={3}>
          {[
            <>
              Back on the Agents page, the server appears and shows as <strong>Online</strong> within a minute.
            </>,
          ]}
        </Steps>
      </GuideSection>

      <GuideSection guide="agents" id="status">
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Status</TableHead>
                <TableHead>What it means</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {STATUSES.map(([status, meaning]) => (
                <TableRow key={status}>
                  <TableCell className="font-medium whitespace-nowrap!">{status}</TableCell>
                  <TableCell className="whitespace-normal">{meaning}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
        <p className="text-muted-foreground">
          If a server is retired or may have been compromised, revoke its Agent from the Agents page. Older Agents also ignore Deployment Parameters (see{" "}
          <GuideLink guide="deployment-scripts" section="safety">
            Writing Deployment Scripts
          </GuideLink>
          ).
        </p>
      </GuideSection>

      <GuideSection guide="agents" id="trouble">
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>If you see</TableHead>
                <TableHead>Do this</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {TROUBLE.map(([see, fix]) => (
                <TableRow key={see}>
                  <TableCell className="whitespace-normal">{see}</TableCell>
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
