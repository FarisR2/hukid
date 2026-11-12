SET LOCAL ROLE hukid_owner;
ALTER TABLE console_auth.session_families
  ADD COLUMN refresh_lease uuid,
  ADD COLUMN refresh_deadline timestamptz,
  ADD CONSTRAINT refresh_lease_complete CHECK ((refresh_lease IS NULL) = (refresh_deadline IS NULL));
-- Cookie/CSRF hashes on inactive generations are logout-only tombstones.
CREATE UNIQUE INDEX sessions_one_active_per_family ON console_auth.sessions(family_id) WHERE state='active';
