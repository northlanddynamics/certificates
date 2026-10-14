import { useQuery } from "@tanstack/react-query";
import { KeyRoundIcon, PlusIcon, ShieldAlertIcon } from "lucide-react";
import { useState, type FormEvent, type ReactNode } from "react";
import QRCodeModule from "react-qr-code";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";
import { authClient, unwrap } from "@/lib/auth-client";
import { useAction } from "@/lib/use-action";

// The package is CommonJS: depending on the bundler, its default export arrives as the component or as the module holding it.
const QRCode = (QRCodeModule as unknown as { default?: typeof QRCodeModule }).default ?? QRCodeModule;

/**
 * The signed-in user's own sign-in methods: an authenticator app (TOTP) as a second factor for their password, and
 * passkeys, which sign in on their own. Each change is an Audit Event in every Organization of theirs. When an
 * Organization of theirs requires MFA and they have a password, this is the one page open to them until they enroll.
 */
export function AccountSecurityPage() {
  const me = useQuery({ queryKey: ["me"], queryFn: api.me });
  const mfa = me.data?.user.mfa;

  return (
    <div className="flex max-w-3xl flex-col gap-6">
      <h1 className="text-xl font-semibold">Account security</h1>
      {mfa?.enrollmentRequired && (
        <Alert variant="destructive">
          <ShieldAlertIcon />
          <AlertTitle>Set up an authenticator app to continue</AlertTitle>
          <AlertDescription>An Organization you belong to requires multi-factor authentication for everyone who signs in with a password.</AlertDescription>
        </Alert>
      )}
      {mfa && <AuthenticatorApp enabled={mfa.enabled} />}
      <Passkeys />
    </div>
  );
}

function AuthenticatorApp({ enabled }: { enabled: boolean }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          Authenticator app {enabled ? <Badge>On</Badge> : <Badge variant="secondary">Off</Badge>}
        </CardTitle>
        <CardDescription>When it is on, signing in with your password also asks for a code from an app such as 1Password, Google Authenticator or Microsoft Authenticator.</CardDescription>
        <CardAction>{enabled ? null : <SetUpAuthenticator />}</CardAction>
      </CardHeader>
      {enabled && (
        <CardContent className="flex flex-wrap gap-2">
          <NewBackupCodes />
          <TurnOffAuthenticator />
        </CardContent>
      )}
    </Card>
  );
}

/** Asks for the password, then shows the secret as a QR code and backup codes, then asks for the app's first code. */
function SetUpAuthenticator() {
  const [open, setOpen] = useState(false);
  const [password, setPassword] = useState("");
  const [secret, setSecret] = useState<{ totpURI: string; backupCodes: string[] } | null>(null);
  const [code, setCode] = useState("");
  const begin = useAction(async () => {
    const enabled = await unwrap(authClient.twoFactor.enable({ password }));
    if (enabled.method === "totp") setSecret({ totpURI: enabled.totpURI, backupCodes: enabled.backupCodes });
  }, []);
  const verify = useAction(() => unwrap(authClient.twoFactor.verifyTotp({ code })), ["me"], () => setOpen(false));
  const reset = () => {
    setPassword("");
    setSecret(null);
    setCode("");
    begin.reset();
    verify.reset();
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        setOpen(o);
        if (!o) reset();
      }}
    >
      <DialogTrigger asChild>
        <Button>Set up</Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Set up an authenticator app</DialogTitle>
          <DialogDescription>{secret ? "Scan the code with your app, keep the backup codes somewhere safe, then enter the code the app shows." : "Confirm your password to begin."}</DialogDescription>
        </DialogHeader>
        {secret === null ? (
          <PasswordForm id="totp-password" password={password} setPassword={setPassword} error={begin.error} onSubmit={() => begin.mutate(undefined)} />
        ) : (
          <form
            id="totp-verify"
            className="flex flex-col gap-4"
            onSubmit={(e: FormEvent) => {
              e.preventDefault();
              verify.mutate(undefined);
            }}
          >
            <div className="self-center rounded-md bg-white p-3">
              <QRCode value={secret.totpURI} size={160} />
            </div>
            <p className="text-center text-xs break-all text-muted-foreground">Can't scan it? Enter this key: {new URL(secret.totpURI).searchParams.get("secret")}</p>
            <BackupCodes codes={secret.backupCodes} />
            <div className="flex flex-col gap-2">
              <Label htmlFor="totp-code">Code from the app</Label>
              <Input id="totp-code" autoComplete="one-time-code" inputMode="numeric" value={code} onChange={(e) => setCode(e.target.value.trim())} required />
            </div>
            {verify.error && <p className="text-sm text-destructive">{verify.error.message || "That code is not right."}</p>}
          </form>
        )}
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline">Cancel</Button>
          </DialogClose>
          {secret === null ? (
            <Button type="submit" form="totp-password" disabled={begin.isPending}>
              Continue
            </Button>
          ) : (
            <Button type="submit" form="totp-verify" disabled={verify.isPending}>
              Turn on
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function NewBackupCodes() {
  const [codes, setCodes] = useState<string[] | null>(null);
  return (
    <PasswordAction
      trigger={<Button variant="outline">New backup codes</Button>}
      title="New backup codes"
      description={codes ? "Keep these somewhere safe. Each works once, and your old codes no longer work." : "Your old backup codes stop working. Confirm your password to continue."}
      confirmLabel="Make new codes"
      action={(password) => unwrap(authClient.twoFactor.generateBackupCodes({ password })).then((r) => setCodes(r.backupCodes))}
      done={codes ? <BackupCodes codes={codes} /> : null}
      onClose={() => setCodes(null)}
    />
  );
}

function TurnOffAuthenticator() {
  return (
    <PasswordAction
      trigger={<Button variant="outline">Turn off</Button>}
      title="Turn off the authenticator app?"
      description="Signing in with your password will no longer ask for a code. If an Organization of yours requires it, you will have to set it up again before going on."
      confirmLabel="Turn off"
      action={(password) => unwrap(authClient.twoFactor.disable({ password }))}
      closeOnDone
    />
  );
}

/** A dialog that asks for the password and does `action` with it; `done` is shown once it has, instead of closing, unless `closeOnDone`. */
function PasswordAction(props: {
  trigger: ReactNode;
  title: string;
  description: string;
  confirmLabel: string;
  action: (password: string) => Promise<unknown>;
  done?: ReactNode;
  closeOnDone?: boolean;
  onClose?: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [password, setPassword] = useState("");
  const act = useAction(() => props.action(password), ["me"], () => props.closeOnDone && setOpen(false));
  const id = `password-${props.confirmLabel.replace(/\W/g, "-")}`;
  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        setOpen(o);
        if (!o) {
          setPassword("");
          act.reset();
          props.onClose?.();
        }
      }}
    >
      <DialogTrigger asChild>{props.trigger}</DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{props.title}</DialogTitle>
          <DialogDescription>{props.description}</DialogDescription>
        </DialogHeader>
        {props.done ?? <PasswordForm id={id} password={password} setPassword={setPassword} error={act.error} onSubmit={() => act.mutate(undefined)} />}
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline">{props.done ? "Done" : "Cancel"}</Button>
          </DialogClose>
          {!props.done && (
            <Button type="submit" form={id} disabled={act.isPending}>
              {props.confirmLabel}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function PasswordForm({ id, password, setPassword, error, onSubmit }: { id: string; password: string; setPassword: (p: string) => void; error: Error | null; onSubmit: () => void }) {
  return (
    <form
      id={id}
      className="flex flex-col gap-2"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        onSubmit();
      }}
    >
      <Label htmlFor={`${id}-input`}>Password</Label>
      <Input id={`${id}-input`} type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required autoFocus />
      {error && <p className="text-sm text-destructive">{error.message || "That did not work."}</p>}
    </form>
  );
}

function BackupCodes({ codes }: { codes: string[] }) {
  return (
    <div className="flex flex-col gap-2">
      <Label>Backup codes</Label>
      <p className="text-xs text-muted-foreground">Each answers the second factor once, if you lose your app.</p>
      <pre className="grid grid-cols-2 gap-1 rounded-md bg-muted p-3 font-mono text-sm">{codes.map((c) => <span key={c}>{c}</span>)}</pre>
    </div>
  );
}

interface Passkey {
  id: string;
  name?: string | null;
  createdAt?: string | Date | null;
}

function Passkeys() {
  const passkeys = useQuery({ queryKey: ["passkeys"], queryFn: () => unwrap(authClient.passkey.listUserPasskeys()) as Promise<Passkey[]> });
  return (
    <Card>
      <CardHeader>
        <CardTitle>Passkeys</CardTitle>
        <CardDescription>A passkey signs you in with your device's fingerprint, face or PIN, without your password.</CardDescription>
        <CardAction>
          <AddPasskey />
        </CardAction>
      </CardHeader>
      <CardContent className="flex flex-col divide-y">
        {passkeys.isPending && <p className="text-sm text-muted-foreground">Loading…</p>}
        {passkeys.data?.length === 0 && <p className="text-sm text-muted-foreground">You have no passkeys yet.</p>}
        {passkeys.data?.map((p) => (
          <div key={p.id} className="flex items-center gap-3 py-2">
            <KeyRoundIcon className="size-4 text-muted-foreground" />
            <div className="flex flex-1 flex-col">
              <span className="font-medium">{p.name || "Passkey"}</span>
              {p.createdAt && <span className="text-xs text-muted-foreground">Added {new Date(p.createdAt).toLocaleDateString()}</span>}
            </div>
            <RenamePasskey passkey={p} />
            <RemovePasskey passkey={p} />
          </div>
        ))}
        {passkeys.error && <p className="text-sm text-destructive">{passkeys.error.message}</p>}
      </CardContent>
    </Card>
  );
}

function AddPasskey() {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const add = useAction(() => unwrap(authClient.passkey.addPasskey({ name: name || undefined })), ["passkeys"], () => setOpen(false));
  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        setOpen(o);
        if (!o) {
          setName("");
          add.reset();
        }
      }}
    >
      <DialogTrigger asChild>
        <Button variant="outline">
          <PlusIcon />
          Add a passkey
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add a passkey</DialogTitle>
          <DialogDescription>Your browser will ask you to create it on this device or another one.</DialogDescription>
        </DialogHeader>
        <form
          id="add-passkey"
          className="flex flex-col gap-2"
          onSubmit={(e: FormEvent) => {
            e.preventDefault();
            add.mutate(undefined);
          }}
        >
          <Label htmlFor="passkey-name">Name</Label>
          <Input id="passkey-name" placeholder="Work laptop" value={name} onChange={(e) => setName(e.target.value)} maxLength={100} />
          {add.error && <p className="text-sm text-destructive">{add.error.message || "The passkey was not added."}</p>}
        </form>
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline">Cancel</Button>
          </DialogClose>
          <Button type="submit" form="add-passkey" disabled={add.isPending}>
            Continue
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function RenamePasskey({ passkey }: { passkey: Passkey }) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState(passkey.name ?? "");
  const rename = useAction(() => unwrap(authClient.passkey.updatePasskey({ id: passkey.id, name })), ["passkeys"], () => setOpen(false));
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="ghost" size="sm">
          Rename
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Rename passkey</DialogTitle>
        </DialogHeader>
        <form
          id={`rename-${passkey.id}`}
          className="flex flex-col gap-2"
          onSubmit={(e: FormEvent) => {
            e.preventDefault();
            rename.mutate(undefined);
          }}
        >
          <Label htmlFor={`rename-${passkey.id}-name`}>Name</Label>
          <Input id={`rename-${passkey.id}-name`} value={name} onChange={(e) => setName(e.target.value)} maxLength={100} required />
          {rename.error && <p className="text-sm text-destructive">{rename.error.message}</p>}
        </form>
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline">Cancel</Button>
          </DialogClose>
          <Button type="submit" form={`rename-${passkey.id}`} disabled={rename.isPending}>
            Save
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function RemovePasskey({ passkey }: { passkey: Passkey }) {
  const [open, setOpen] = useState(false);
  const remove = useAction(() => unwrap(authClient.passkey.deletePasskey({ id: passkey.id })), ["passkeys"], () => setOpen(false));
  return (
    <>
      <Button variant="ghost" size="sm" onClick={() => setOpen(true)}>
        Remove
      </Button>
      <ConfirmDialog
        open={open}
        onOpenChange={setOpen}
        title={`Remove ${passkey.name || "this passkey"}?`}
        description="It will no longer sign you in. Remove it from your device or password manager too."
        confirmLabel="Remove"
        pending={remove.isPending}
        error={remove.error}
        onConfirm={() => remove.mutate(undefined)}
      />
    </>
  );
}
