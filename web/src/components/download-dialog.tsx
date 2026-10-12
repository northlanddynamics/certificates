import { DownloadIcon } from "lucide-react";
import { useState, type ReactNode } from "react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Field, FieldLabel } from "@/components/ui/field";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { EXPORT_CHAINS, EXPORT_FORMATS, api } from "@/lib/api";

function Choice({ id, label, value, onChange, choices }: { id: string; label: string; value: string; onChange: (value: string) => void; choices: [string, string][] }) {
  return (
    <Field>
      <FieldLabel htmlFor={id}>{label}</FieldLabel>
      <Select value={value} onValueChange={onChange}>
        <SelectTrigger id={id} className="w-full">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {choices.map(([v, text]) => (
            <SelectItem key={v} value={v}>
              {text}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </Field>
  );
}

/**
 * Downloads a Certificate of a Managed Certificate, in the format and with the chain chosen: the current one, or the one
 * with `certificateId`. The trigger is the button that opens the dialog (a default one if none is given).
 */
export function DownloadDialog({ orgId, id, certificateId, trigger }: { orgId: string; id: string; certificateId?: string; trigger?: ReactNode }) {
  const [open, setOpen] = useState(false);
  const [format, setFormat] = useState("pem");
  const [chain, setChain] = useState("with-intermediates");
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        {trigger ?? (
          <Button variant="outline">
            <DownloadIcon />
            Download
          </Button>
        )}
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Download Certificate</DialogTitle>
          <DialogDescription>The platform holds no private key, so the download never contains one.</DialogDescription>
        </DialogHeader>
        <div className="flex flex-col gap-4">
          <Choice id={`download-format-${certificateId ?? "current"}`} label="Format" value={format} onChange={setFormat} choices={EXPORT_FORMATS} />
          <Choice id={`download-chain-${certificateId ?? "current"}`} label="Chain" value={chain} onChange={setChain} choices={EXPORT_CHAINS} />
        </div>
        <DialogFooter>
          <Button type="button" variant="outline" onClick={() => setOpen(false)}>
            Cancel
          </Button>
          <Button asChild>
            <a href={api.certificateDownloadUrl(orgId, id, { format, chain }, certificateId)} download onClick={() => setOpen(false)}>
              Download
            </a>
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
