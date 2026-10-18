import { useParams } from "@tanstack/react-router";
import { CsrGenerator } from "@/components/csr-generator";
import { PrototypeSwitcher, usePrototypeVariant } from "@/components/prototype-switcher";
import { TOOLS_VARIANTS, ToolsVariantB, ToolsVariantC } from "./csr-tools.prototype";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

/** A key and a CSR made in the browser, for anyone who keeps their own key. Nothing here talks to the platform. */
export function CsrToolsPage() {
  // PROTOTYPE: `?variant=` picks one of the alternatives in csr-tools.prototype.tsx.
  const variant = usePrototypeVariant(TOOLS_VARIANTS);
  const { orgId } = useParams({ strict: false }) as { orgId: string };
  const switcher = <PrototypeSwitcher title="CSR Generator page" variants={TOOLS_VARIANTS} />;
  if (variant === "B") return <>{switcher}<ToolsVariantB /></>;
  if (variant === "C") return <>{switcher}<ToolsVariantC key={orgId} orgId={orgId} /></>;
  return (
    <div className="flex max-w-2xl flex-col gap-6">
      {switcher}
      <h1 className="text-xl font-semibold">CSR Generator</h1>
      <Card>
        <CardHeader>
          <CardTitle>Make a key and a CSR</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <p className="text-sm text-muted-foreground">
            The key is generated in your browser and never sent to the platform, which cannot recover it for you. Keep it, and give the CSR to whoever signs it,
            or paste it into a Managed Certificate that keeps its own key.
          </p>
          <CsrGenerator />
        </CardContent>
      </Card>
    </div>
  );
}
