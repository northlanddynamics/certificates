import { EmptySection } from "@/components/empty-section";

// Activity is built in its own ticket; until then it says what is coming.
export const ActivityTab = () => <p className="text-sm text-muted-foreground">This Managed Certificate's history and Issuance attempts will be listed here.</p>;

export const ServicesTab = () => (
  <EmptySection title="Services">Deployments, and the Agents and Endpoints they run on, will appear here.</EmptySection>
);
