import { useMutation, useQueryClient } from "@tanstack/react-query";

/** A mutation that, once it succeeds, refetches the queries under the given keys. */
export function useAction<A>(fn: (arg: A) => Promise<unknown>, invalidate: string[], onDone?: () => void) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: fn,
    onSuccess: async () => {
      onDone?.();
      await Promise.all(invalidate.map((k) => queryClient.invalidateQueries({ queryKey: [k] })));
    },
  });
}
