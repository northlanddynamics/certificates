// What an Enrollment Profile (enrollment-profiles.ts) can put in the Device Certificates it issues, and the keys it
// certifies. A new value is an entry here. The web imports these too, so that what it offers is what the API accepts;
// this module imports nothing, so either side can.

/**
 * Every kind of issuer (enrollment-issuer.ts) a profile can have. A new kind is an entry here, which the database checks
 * on `enrollment_profile.issuer_kind` and `device_certificate.issuer_kind` (schema.ts) must list too.
 */
export const ENROLLMENT_ISSUER_KINDS = [
  /** An Issuing CA of one of the Organization's Private CAs. */
  "private_ca",
  /** One of the Organization's ADCS CAs, under one of its Certificate Templates, reached only through Agents. */
  "adcs",
] as const;
export type EnrollmentIssuerKind = (typeof ENROLLMENT_ISSUER_KINDS)[number];

/** The key usages a profile may give its Device Certificates (RFC 5280, 4.2.1.3); no CA usages. */
export const DEVICE_KEY_USAGES = ["digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment", "keyAgreement"] as const;
export type DeviceKeyUsage = (typeof DEVICE_KEY_USAGES)[number];
/** What an RSA client authentication certificate (Wi-Fi, VPN) needs. */
export const DEFAULT_DEVICE_KEY_USAGES: DeviceKeyUsage[] = ["digitalSignature", "keyEncipherment"];

/** The extended key usages a profile may give its Device Certificates, by name, and their OIDs. */
export const DEVICE_EXTENDED_KEY_USAGES = {
  clientAuth: "1.3.6.1.5.5.7.3.2",
  serverAuth: "1.3.6.1.5.5.7.3.1",
  emailProtection: "1.3.6.1.5.5.7.3.4",
  ipsecIKE: "1.3.6.1.5.5.7.3.17",
  smartcardLogon: "1.3.6.1.4.1.311.20.2.2",
} as const;
export type DeviceExtendedKeyUsage = keyof typeof DEVICE_EXTENDED_KEY_USAGES;
export const DEVICE_EXTENDED_KEY_USAGE_NAMES = Object.keys(DEVICE_EXTENDED_KEY_USAGES) as [DeviceExtendedKeyUsage, ...DeviceExtendedKeyUsage[]];
export const DEFAULT_DEVICE_EXTENDED_KEY_USAGES: DeviceExtendedKeyUsage[] = ["clientAuth"];

/**
 * The device keys a profile may certify. Only RSA: SCEP encrypts its response to the device's key, which only RSA
 * can do. The names are those of the platform's key algorithms (csr.ts), and rsa-1024, which Apple's SCEP payload
 * makes unless told otherwise.
 */
export const DEVICE_KEY_TYPES = ["rsa-1024", "rsa-2048", "rsa-3072", "rsa-4096"] as const;
export type DeviceKeyType = (typeof DEVICE_KEY_TYPES)[number];
/** The weak key: one that can be broken. A profile allows it only when told to, and its Device Certificates are marked. */
export const WEAK_DEVICE_KEY_TYPE = "rsa-1024" satisfies DeviceKeyType;
/** What a profile allows unless told otherwise: every key that is not weak. */
export const DEFAULT_DEVICE_KEY_TYPES: DeviceKeyType[] = DEVICE_KEY_TYPES.filter((type) => type !== WEAK_DEVICE_KEY_TYPE);
export const DEVICE_KEY_TYPE_LABELS: Record<DeviceKeyType, string> = { "rsa-1024": "RSA 1024", "rsa-2048": "RSA 2048", "rsa-3072": "RSA 3072", "rsa-4096": "RSA 4096" };

/** How long a Device Certificate is valid for unless the profile says otherwise, and at most, in days. */
export const DEFAULT_DEVICE_VALIDITY_DAYS = 365;
export const MAX_DEVICE_VALIDITY_DAYS = 1825;
/** The default when the profile's validator's kind uses a Shared Challenge: nothing revokes those certificates automatically (ADR 0008). */
export const DEFAULT_SHARED_CHALLENGE_VALIDITY_DAYS = 90;

/** How many days after its end a Device Certificate is pruned unless the profile says otherwise, and at most. */
export const DEFAULT_DEVICE_RETENTION_DAYS = 365;
export const MAX_DEVICE_RETENTION_DAYS = 3650;
