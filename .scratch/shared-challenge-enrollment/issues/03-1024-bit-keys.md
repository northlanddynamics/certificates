# 03: 1024-bit keys

**What to build:** An Organization Administrator may let an Enrollment Profile accept 1024-bit RSA device keys, which no profile does unless chosen, with a warning when they choose it; Device Certificates with such keys are marked "Weak key" and can be filtered for. A refusal for a disallowed key says what was sent and what is allowed. See `spec.md`, "1024-bit keys".

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] `rsa-1024` is a device key type a profile may allow; the default allowed key types stay RSA 2048, 3072 and 4096.
- [ ] The profile form warns, when `rsa-1024` is chosen, that 1024-bit keys are breakable and that some RADIUS servers and VPN gateways reject them.
- [ ] A request with a key the profile does not allow is refused with a reason naming the key's type and size and the allowed key types, in the CertRep and in `enrollment.refused`.
- [ ] A profile allowing `rsa-1024` issues to a 1024-bit key.
- [ ] Each Device Certificate records its key type; the API returns it, `device_certificate.issued` carries `keyType`, and the list takes a weak-key filter.
- [ ] The Device Certificate list shows a "Weak key" badge for 1024-bit keys and offers the filter.
- [ ] Allowing `rsa-1024` appears in the profile's created and updated Audit Events as key types already do.
