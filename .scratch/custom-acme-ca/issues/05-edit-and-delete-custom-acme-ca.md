# 05: Edit and delete a custom ACME CA

**What to build:** An Organization Administrator can rename a custom ACME CA and change its contact email and tag, and delete one that nothing refers to.

**Blocked by:** 03

**Status:** ready-for-agent

- [ ] Name, contact email and tag are editable; the directory URL and External Account Binding are not, and the form says to delete and recreate instead.
- [ ] Deletion is refused, with the reason, while any Managed Certificate or Certificate refers to the CA; otherwise it removes the CA, its account and its Secrets.
- [ ] The built-in CAs cannot be edited or deleted.
- [ ] The `acmeAccount` permission gains `update` and `delete`, held only by Organization Administrators, and `/api/me` reports them.
- [ ] Editing and deleting each write an Audit Event.
- [ ] Server tests cover edit, delete, delete refused while referenced, built-ins untouched, permissions and Audit Events.
