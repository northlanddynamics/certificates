// How to make a Private CA's root trusted on the platforms relying parties commonly run, for the Private CAs guide and
// the "Trust this root" dialog. `file` stands for the downloaded root's name: PEM ends .pem, DER ends .crt.
export interface TrustStore {
  id: string;
  label: string;
  /** For many machines, and what to do for one. */
  how: string;
  command: (file: { pem: string; der: string }) => string;
}

export const TRUST_STORES: TrustStore[] = [
  {
    id: "windows",
    label: "Windows",
    how: "For many machines, publish it with Group Policy under Trusted Root Certification Authorities. For one machine, as an administrator:",
    command: ({ der }) => `certutil -addstore -f Root ${der}`,
  },
  {
    id: "macos",
    label: "macOS",
    how: "For managed Macs, deliver it in a configuration profile from your device management platform. For one Mac:",
    command: ({ der }) => `sudo security add-trusted-cert -d -r trustRoot \\\n  -k /Library/Keychains/System.keychain ${der}`,
  },
  {
    id: "debian",
    label: "Debian / Ubuntu",
    how: "Copy the PEM file in with a .crt extension, then rebuild the bundle:",
    command: ({ pem }) => `sudo cp ${pem} /usr/local/share/ca-certificates/${pem.replace(/\.pem$/, ".crt")}\nsudo update-ca-certificates`,
  },
  {
    id: "rhel",
    label: "RHEL / Fedora",
    how: "Copy the PEM file into the trust anchors, then rebuild the bundle:",
    command: ({ pem }) => `sudo cp ${pem} /etc/pki/ca-trust/source/anchors/\nsudo update-ca-trust`,
  },
  {
    id: "java",
    label: "Java",
    how: "Import it into the trust store of each Java runtime that connects:",
    command: ({ der }) => `keytool -importcert -alias private-ca-root -file ${der} \\\n  -cacerts -noprompt`,
  },
  {
    id: "firefox",
    label: "Firefox",
    how: "Firefox keeps its own store. For managed installs, use the Certificates › Install enterprise policy, or allow the operating system's roots:",
    command: () => `"policies": { "Certificates": { "ImportEnterpriseRoots": true } }`,
  },
];
