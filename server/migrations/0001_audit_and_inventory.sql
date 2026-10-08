-- Managed Certificates are scoped to an Organization; every query filters by it.
create table managed_certificate (
  id uuid primary key default gen_random_uuid(),
  organization_id text not null references organization (id),
  created_at timestamptz not null default now()
);
create index managed_certificate_org_idx on managed_certificate (organization_id);

-- Append-only audit log, one row per state change, written in the same
-- transaction as the change it records.
create table audit_event (
  id bigint generated always as identity primary key,
  organization_id text not null references organization (id),
  occurred_at timestamptz not null,
  actor_id text,
  actor_email text,
  action text not null,
  target_type text not null,
  target_id text,
  detail jsonb not null default '{}'
);
create index audit_event_org_idx on audit_event (organization_id, id);

create function audit_event_append_only() returns trigger as $$
begin
  raise exception 'audit_event is append-only';
end;
$$ language plpgsql;

create trigger audit_event_no_update_delete
  before update or delete on audit_event
  for each row execute function audit_event_append_only();
