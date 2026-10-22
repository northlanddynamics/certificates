# 05: Edit and delete a custom ACME CA

**What to build:** An Organization Administrator can rename a custom ACME CA and change its contact email and tag, and delete one that nothing refers to.

**Blocked by:** 03

**Status:** done

- [x] Name, contact email and tag are editable; the directory URL and External Account Binding are not, and the form says to delete and recreate instead.
- [x] Deletion is refused, with the reason, while any Managed Certificate or Certificate refers to the CA; otherwise it removes the CA, its account and its Secrets.
- [x] The built-in CAs cannot be edited or deleted.
- [x] The `acmeAccount` permission gains `update` and `delete`, held only by Organization Administrators, and `/api/me` reports them.
- [x] Editing and deleting each write an Audit Event.
- [x] Server tests cover edit, delete, delete refused while referenced, built-ins untouched, permissions and Audit Events.

## Comments

Implemented: `PATCH` and `DELETE /api/organizations/{orgId}/acme-cas/{acmeCaId}`. A new contact email is sent to the CA (ACME account update) before it is saved. Deleting removes the account, its key and any EAB HMAC key Secret, and leaves the account at the CA as it is. Known gap: a Managed Certificate created on the CA at the same moment as the deletion is not locked out (issuer resolution takes no lock on the CA row).
