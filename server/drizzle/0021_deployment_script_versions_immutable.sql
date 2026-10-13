-- A version of a Deployment Script is never changed or removed (ADR 0004: an Agent checks the hash of what it runs, and what it
-- was told to run must always be showable). No route does either; this makes the database refuse it too.
CREATE FUNCTION deployment_script_version_immutable() RETURNS trigger AS $$
BEGIN
	RAISE EXCEPTION 'a Deployment Script version is immutable';
END;
$$ LANGUAGE plpgsql;
--> statement-breakpoint
CREATE TRIGGER deployment_script_version_immutable
BEFORE UPDATE OR DELETE ON "deployment_script_version"
FOR EACH ROW EXECUTE FUNCTION deployment_script_version_immutable();
