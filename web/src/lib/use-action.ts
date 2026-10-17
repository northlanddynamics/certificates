import { useMutation, useQueryClient } from "@tanstack/react-query";

/** A mutation that, once it succeeds, refetches the queries under the given keys. */
export function useAction<A, R = unknown>(fn: (arg: A) => Promise<R>, invalidate: string[], onDone?: (result: R) => void) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: fn,
    onSuccess: async (result) => {
      onDone?.(result);
      await Promise.all(invalidate.map((k) => queryClient.invalidateQueries({ queryKey: [k] })));
    },
  });
}
