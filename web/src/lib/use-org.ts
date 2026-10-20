import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";

/** The caller's membership of the Organization `orgId`, with what they may do there; none until `me` is read, or if they are not in it. */
export const useOrg = (orgId: string) => useQuery({ queryKey: ["me"], queryFn: api.me, select: (me) => me.organizations.find((o) => o.id === orgId) }).data;
