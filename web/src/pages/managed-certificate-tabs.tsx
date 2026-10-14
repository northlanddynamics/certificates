import { EmptySection } from "@/components/empty-section";

// Issued certificates and Activity are built in their own tickets; until then each says what is coming.
export const IssuedCertificatesTab = () => <p className="text-sm text-muted-foreground">The Certificates issued for this Managed Certificate will be listed here.</p>;
export const ActivityTab = () => <p className="text-sm text-muted-foreground">This Managed Certificate's history and Issuance attempts will be listed here.</p>;

export const ServicesTab = () => (
  <EmptySection title="Services">Deployments, and the Agents and Endpoints they run on, will appear here.</EmptySection>
);
