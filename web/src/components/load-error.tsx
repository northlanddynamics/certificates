import { CloudAlertIcon, RotateCwIcon } from "lucide-react";
import type { ReactNode } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";

/** What could not load, centred where it would have been, with Try again and whatever else the place offers (such as Sign out). */
export function LoadError({
  title,
  description,
  onRetry,
  retrying,
  children,
}: {
  title: string;
  description: ReactNode;
  onRetry: () => void;
  retrying: boolean;
  children?: ReactNode;
}) {
  return (
    <Card role="alert" className="mx-auto mt-16 w-full max-w-sm">
      <CardHeader>
        <CloudAlertIcon className="mb-1 size-6 text-muted-foreground" aria-hidden />
        <CardTitle>{title}</CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardFooter className="gap-2">
        <Button onClick={onRetry} disabled={retrying}>
          <RotateCwIcon className={retrying ? "animate-spin" : undefined} />
          Try again
        </Button>
        {children}
      </CardFooter>
    </Card>
  );
}
