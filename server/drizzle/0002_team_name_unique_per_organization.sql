-- Custom migration: Team names are unique within an Organization, ignoring case.
-- (The team table comes from Better Auth's schema, which has no such constraint.)
CREATE UNIQUE INDEX team_organization_name_unique ON team (organization_id, lower(name));
