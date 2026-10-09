-- Custom migration: a Certificate is immutable once stored; reject any UPDATE or DELETE.
CREATE FUNCTION certificate_immutable() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'certificate is immutable';
END;
$$ LANGUAGE plpgsql;
--> statement-breakpoint
CREATE TRIGGER certificate_no_update_delete
  BEFORE UPDATE OR DELETE ON certificate
  FOR EACH ROW EXECUTE FUNCTION certificate_immutable();
