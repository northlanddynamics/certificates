import { ClipboardPasteIcon, UploadIcon, XIcon } from "lucide-react";
import { useEffect, useRef, useState, type DragEvent } from "react";
import { InputGroup, InputGroupAddon, InputGroupButton, InputGroupText, InputGroupTextarea } from "@/components/ui/input-group";
import { readCsrFile, readCsrText } from "@/lib/csr-input";

const isEditable = (target: EventTarget | null) => target instanceof HTMLElement && (target.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName));

/**
 * Takes a CSR typed, pasted (into the box, or anywhere on the page), chosen as a file, or dropped on the box, whether
 * PEM or DER, and hands its text up. A private key is never kept: it is cleared and the user is told. Nothing is sent
 * anywhere; the text goes only to `onChange`.
 */
export function CsrDropField({ id, value, onChange }: { id: string; value: string; onChange: (text: string) => void }) {
  const [dragging, setDragging] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  // The latest handler, so the page-level listener below is added once.
  const accept = (text: string) => {
    const read = readCsrText(text);
    if (read?.kind === "refused" && read.clear) {
      onChange("");
      setNotice(read.problem);
      return;
    }
    setNotice(null);
    onChange(text);
  };
  const acceptRef = useRef(accept);
  acceptRef.current = accept;

  // Pasting with nothing focused, as after opening the page with a CSR on the clipboard, fills the box all the same.
  useEffect(() => {
    const onPaste = (e: ClipboardEvent) => {
      if (isEditable(e.target)) return;
      const text = e.clipboardData?.getData("text");
      if (text) acceptRef.current(text);
    };
    document.addEventListener("paste", onPaste);
    return () => document.removeEventListener("paste", onPaste);
  }, []);

  async function acceptFile(file: File) {
    const read = await readCsrFile(file);
    if ("problem" in read) setNotice(read.problem);
    else accept(read.text);
  }

  function onDrop(e: DragEvent) {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) void acceptFile(file);
    else accept(e.dataTransfer.getData("text/plain"));
  }

  return (
    <div className="flex flex-col gap-2">
      <InputGroup
        data-dragging={dragging}
        className="data-[dragging=true]:border-dashed data-[dragging=true]:border-ring data-[dragging=true]:ring-3 data-[dragging=true]:ring-ring/50"
        onDragEnter={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragOver={(e) => e.preventDefault()}
        // Leaving for one of the box's own children is not leaving the box.
        onDragLeave={(e) => !e.currentTarget.contains(e.relatedTarget as Node | null) && setDragging(false)}
        onDrop={onDrop}
      >
        <InputGroupTextarea
          id={id}
          rows={10}
          spellCheck={false}
          autoComplete="off"
          className="max-h-72 min-h-48 font-mono text-xs field-sizing-fixed"
          placeholder={"-----BEGIN CERTIFICATE REQUEST-----\n\nPaste a CSR here, or drop a .csr or .pem file on this box."}
          aria-label="CSR (PEM or DER file)"
          value={value}
          onChange={(e) => accept(e.target.value)}
        />
        {dragging && <div className="pointer-events-none absolute inset-0 flex items-center justify-center rounded-lg bg-background/80 text-sm font-medium">Drop to read this CSR</div>}
        <InputGroupAddon align="block-end" className="flex-wrap border-t">
          <input
            ref={fileInput}
            type="file"
            hidden
            accept=".csr,.pem,.req,.txt,.der"
            onChange={(e) => {
              const file = e.target.files?.[0];
              // So that choosing the same file again reads it again.
              e.target.value = "";
              if (file) void acceptFile(file);
            }}
          />
          <InputGroupButton variant="outline" onClick={() => fileInput.current?.click()}>
            <UploadIcon />
            Choose file
          </InputGroupButton>
          <InputGroupButton
            variant="outline"
            onClick={() =>
              navigator.clipboard.readText().then(accept, () => setNotice("The browser would not let this page read the clipboard. Press Ctrl+V (⌘V on a Mac) in the box instead."))
            }
          >
            <ClipboardPasteIcon />
            Paste
          </InputGroupButton>
          <InputGroupText className="text-xs">PEM or DER; read in this browser</InputGroupText>
          {value !== "" && (
            <InputGroupButton
              className="ml-auto"
              onClick={() => {
                setNotice(null);
                onChange("");
              }}
            >
              <XIcon />
              Clear
            </InputGroupButton>
          )}
        </InputGroupAddon>
      </InputGroup>
      {notice && (
        <p role="status" className="text-sm text-destructive">
          {notice}
        </p>
      )}
    </div>
  );
}
