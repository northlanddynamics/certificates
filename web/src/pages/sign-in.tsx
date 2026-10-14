import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { KeyRoundIcon, LogInIcon } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { ApiError } from "@/lib/api";
import { authClient, unwrap } from "@/lib/auth-client";

/** Why an SSO sign-in came back here, as the identity provider or the platform put it in the URL. */
const ssoFailure = () => {
  const params = new URLSearchParams(window.location.search);
  const error = params.get("error");
  return error ? (params.get("error_description") ?? error).replaceAll("_", " ") : null;
};

/**
 * Sign in with a password (and, once set up, a code from an authenticator app or a backup code), with a passkey alone, or
 * through the SSO connection of the email's domain. An Organization that requires SSO refuses its members the others.
 */
export function SignInPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  // Set once the password is right and a second factor is asked for.
  const [secondFactor, setSecondFactor] = useState(false);
  const done = async () => {
    await queryClient.invalidateQueries({ queryKey: ["me"] });
    await navigate({ to: "/" });
  };
  const signIn = useMutation({
    mutationFn: () => unwrap(authClient.signIn.email({ email, password })),
    onSuccess: async (data) => {
      if (data && "twoFactorRedirect" in data && data.twoFactorRedirect) setSecondFactor(true);
      else await done();
    },
  });
  const withPasskey = useMutation({ mutationFn: () => unwrap(authClient.signIn.passkey()), onSuccess: done });
  // The browser leaves for the identity provider, which sends it back to the platform and then home, or here with an error.
  const withSso = useMutation({
    mutationFn: () =>
      unwrap(authClient.signIn.sso({ email, callbackURL: `${window.location.origin}/`, errorCallbackURL: `${window.location.origin}/sign-in` })),
  });
  const [returnedWith] = useState(ssoFailure);
  const ssoRequired = [signIn.error, withPasskey.error].some((e) => e instanceof ApiError && e.status === 403 && /requires SSO/.test(e.message));

  if (secondFactor) return <SecondFactor onSignedIn={done} onBack={() => setSecondFactor(false)} />;

  return (
    <Card className="mx-auto mt-16 max-w-sm">
      <CardHeader>
        <CardTitle>Sign in</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <form
          className="flex flex-col gap-4"
          onSubmit={(e: FormEvent) => {
            e.preventDefault();
            signIn.mutate();
          }}
        >
          <div className="flex flex-col gap-2">
            <Label htmlFor="email">Email</Label>
            <Input id="email" type="email" autoComplete="username webauthn" value={email} onChange={(e) => setEmail(e.target.value)} required />
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="password">Password</Label>
            <Input id="password" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
          </div>
          {signIn.error && !ssoRequired && <p className="text-sm text-destructive">Sign in failed. Check your email and password.</p>}
          <Button type="submit" disabled={signIn.isPending}>
            Sign in
          </Button>
        </form>
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <Separator className="flex-1" />
          or
          <Separator className="flex-1" />
        </div>
        <Button variant="outline" onClick={() => withPasskey.mutate()} disabled={withPasskey.isPending}>
          <KeyRoundIcon />
          Sign in with a passkey
        </Button>
        {withPasskey.error && !ssoRequired && <p className="text-sm text-destructive">Signing in with a passkey failed.</p>}
        <Button variant="outline" onClick={() => withSso.mutate()} disabled={withSso.isPending || !email}>
          <LogInIcon />
          Sign in with SSO
        </Button>
        {ssoRequired && <p className="text-sm text-destructive">Your Organization requires SSO. Enter your email and sign in with SSO.</p>}
        {withSso.error && <p className="text-sm text-destructive">{withSso.error instanceof ApiError && withSso.error.status === 404 ? "No SSO connection serves that email's domain." : withSso.error.message}</p>}
        {returnedWith && !withSso.error && <p className="text-sm text-destructive">Signing in with SSO failed: {returnedWith}.</p>}
      </CardContent>
    </Card>
  );
}

function SecondFactor({ onSignedIn, onBack }: { onSignedIn: () => Promise<void>; onBack: () => void }) {
  const [useBackupCode, setUseBackupCode] = useState(false);
  const [code, setCode] = useState("");
  const verify = useMutation({
    mutationFn: () => unwrap(useBackupCode ? authClient.twoFactor.verifyBackupCode({ code }) : authClient.twoFactor.verifyTotp({ code })),
    onSuccess: onSignedIn,
  });

  return (
    <Card className="mx-auto mt-16 max-w-sm">
      <CardHeader>
        <CardTitle>Two-factor authentication</CardTitle>
        <CardDescription>{useBackupCode ? "Enter one of your backup codes. Each works once." : "Enter the code from your authenticator app."}</CardDescription>
      </CardHeader>
      <CardContent>
        <form
          className="flex flex-col gap-4"
          onSubmit={(e: FormEvent) => {
            e.preventDefault();
            verify.mutate();
          }}
        >
          <div className="flex flex-col gap-2">
            <Label htmlFor="code">{useBackupCode ? "Backup code" : "Code"}</Label>
            <Input
              id="code"
              autoComplete="one-time-code"
              inputMode={useBackupCode ? "text" : "numeric"}
              value={code}
              onChange={(e) => setCode(e.target.value.trim())}
              required
              autoFocus
            />
          </div>
          {verify.error && <p className="text-sm text-destructive">{verify.error.message || "That code is not right."}</p>}
          <Button type="submit" disabled={verify.isPending}>
            Verify
          </Button>
          <div className="flex justify-between">
            <Button type="button" variant="link" className="px-0" onClick={onBack}>
              Back
            </Button>
            <Button
              type="button"
              variant="link"
              className="px-0"
              onClick={() => {
                setUseBackupCode(!useBackupCode);
                setCode("");
                verify.reset();
              }}
            >
              {useBackupCode ? "Use the authenticator app" : "Use a backup code"}
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}
