import { useParams } from "@tanstack/react-router";
import { useEffect, useRef, type ComponentType } from "react";
import { GuidePanelFrame, GUIDES, sectionElementId, useHelp, type Guide } from "@/components/guide";
import { HelpSheet } from "@/components/help-sheet";
import { AgentGuidePage } from "@/pages/agent-guide";
import { DcvGuidePage } from "@/pages/dcv-guide";
import { DeploymentScriptGuidePage } from "@/pages/deployment-script-guide";
import { DnsProviderGuidePage } from "@/pages/dns-provider-guide";
import { EnrollmentGuidePage } from "@/pages/enrollment-guide";
import { ManagedCertificateGuidePage } from "@/pages/managed-certificate-guide";
import { PrivateCaGuidePage } from "@/pages/private-ca-guide";

const CONTENT: Record<Guide, ComponentType> = {
  "managed-certificates": ManagedCertificateGuidePage,
  agents: AgentGuidePage,
  "dns-providers": DnsProviderGuidePage,
  "deployment-scripts": DeploymentScriptGuidePage,
  "private-cas": PrivateCaGuidePage,
  "enrollment-profiles": EnrollmentGuidePage,
  dcv: DcvGuidePage,
};

/**
 * The help panel: a wide sheet from the right that shows a guide over the page, and over any dialog open on it, which
 * both stay as they are underneath. It opens at the section linked to and follows the address (`useHelp`), so Back
 * closes it. Only on an Organization's pages, whose guides they are.
 */
export function HelpPanel() {
  const { orgId } = useParams({ strict: false });
  const help = useHelp();
  const body = useRef<HTMLDivElement>(null);
  const open = help.guide !== null && orgId !== undefined;
  const Content = help.guide ? CONTENT[help.guide] : null;

  // To the section linked to, once it is drawn; to the top for a guide opened without one.
  useEffect(() => {
    if (!open) return;
    const frame = requestAnimationFrame(() => {
      const target = help.section ? document.getElementById(sectionElementId(help.section, true)) : null;
      if (target) target.scrollIntoView({ block: "start" });
      else body.current?.scrollTo({ top: 0 });
    });
    return () => cancelAnimationFrame(frame);
  }, [open, help.guide, help.section]);

  return (
    <HelpSheet
      open={open}
      onClose={help.close}
      title={`Help: ${help.guide ? GUIDES[help.guide].title : ""}`}
      description="A guide, shown over the page; close it to go on where you were."
      bodyRef={body}
    >
      {Content && (
        <GuidePanelFrame>
          <Content />
        </GuidePanelFrame>
      )}
    </HelpSheet>
  );
}
