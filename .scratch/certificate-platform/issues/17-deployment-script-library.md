# 17: Deployment Script library

**What to build:** Organization Administrators can upload Bash or PowerShell Deployment Scripts to their Organization's library. Every version is immutable and identified by its hash. No other role can upload or edit scripts (ADR 0004).

**Blocked by:** 02 (Members, roles and Teams)

**Status:** done

- [x] Organization Administrators can upload a script with a name and interpreter (Bash or PowerShell), creating a new immutable version identified by its hash.
- [x] Previous versions remain viewable.
- [x] Members, Approvers and Owners are refused when uploading or editing scripts (Seam A test).
- [x] Uploads are audited with the script hash.
