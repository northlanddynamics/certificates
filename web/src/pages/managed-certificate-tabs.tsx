import { EmptySection } from "@/components/empty-section";

// Issued certificates is built in its own ticket; until then it says what is coming.
export const IssuedCertificatesTab = () => <p className="text-sm text-muted-foreground">The Certificates issued for this Managed Certificate will be listed here.</p>;

export const ServicesTab = () => (
  <EmptySection title="Services">Deployments, and the Agents and Endpoints they run on, will appear here.</EmptySection>
);
