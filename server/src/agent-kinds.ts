// What an Agent says about the machine it runs on, and how its version is judged against the latest the platform knows.

/** Agents run on Windows and Linux (macOS is out of scope for v1). */
export const AGENT_OSES = ["linux", "windows"] as const;
export type AgentOs = (typeof AGENT_OSES)[number];
export const AGENT_ARCHES = ["amd64", "arm64"] as const;
export type AgentArch = (typeof AGENT_ARCHES)[number];

/** The newest Agent release the platform knows of, unless the host says otherwise (`AppDeps.agentGateway`). */
export const LATEST_AGENT_VERSION = "0.1.0";

const SEMVER = /^v?(\d+)\.(\d+)\.(\d+)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

/** The numbers of a semantic version, or null when `version` is not one. A pre-release suffix is ignored. */
function parts(version: string): [number, number, number] | null {
  const match = SEMVER.exec(version.trim());
  return match ? [Number(match[1]), Number(match[2]), Number(match[3])] : null;
}

/** Whether `version` is older than `latest`. A version that is not a semantic version one cannot be vouched for, so counts as outdated. */
export function isOutdated(version: string, latest: string): boolean {
  const have = parts(version);
  const want = parts(latest);
  if (!have) return true;
  if (!want) return false;
  for (let i = 0; i < 3; i++) if (have[i]! !== want[i]!) return have[i]! < want[i]!;
  // The same numbers: a pre-release (`0.1.0-dev`) is older than its release.
  return /-/.test(version.split("+")[0]!) && !/-/.test(latest.split("+")[0]!);
}
