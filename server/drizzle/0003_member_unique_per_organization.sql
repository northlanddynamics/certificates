-- Custom migration: a user is a member of an Organization at most once. Better Auth only checks this in
-- application code (read, then write), so two concurrent requests could both pass; the index makes it a fact.
CREATE UNIQUE INDEX member_organization_user_unique ON member (organization_id, user_id);
