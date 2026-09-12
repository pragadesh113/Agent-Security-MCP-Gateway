CREATE TABLE protected_admin_resources (
  resource_id text PRIMARY KEY,
  resource_kind text NOT NULL CHECK (resource_kind IN ('SERVER', 'ROUTE', 'SCHEMA', 'POLICY')),
  created_at timestamptz NOT NULL,
  UNIQUE (resource_id, resource_kind)
);

CREATE TABLE protected_admin_versions (
  resource_id text NOT NULL REFERENCES protected_admin_resources(resource_id),
  resource_kind text NOT NULL CHECK (resource_kind IN ('SERVER', 'ROUTE', 'SCHEMA', 'POLICY')),
  version bigint NOT NULL CHECK (version > 0),
  document jsonb NOT NULL,
  document_digest char(64) NOT NULL CHECK (document_digest ~ '^[a-f0-9]{64}$'),
  created_at timestamptz NOT NULL,
  created_by_identity_digest char(64) NOT NULL CHECK (created_by_identity_digest ~ '^[a-f0-9]{64}$'),
  PRIMARY KEY (resource_id, version),
  UNIQUE (resource_id, resource_kind, version),
  FOREIGN KEY (resource_id, resource_kind)
    REFERENCES protected_admin_resources(resource_id, resource_kind)
);

CREATE TABLE protected_admin_audit_events (
  sequence_id bigserial PRIMARY KEY,
  event_id text NOT NULL UNIQUE,
  resource_id text NOT NULL,
  resource_kind text NOT NULL CHECK (resource_kind IN ('SERVER', 'ROUTE', 'SCHEMA', 'POLICY')),
  version bigint NOT NULL CHECK (version > 0),
  actor_identity_digest char(64) NOT NULL CHECK (actor_identity_digest ~ '^[a-f0-9]{64}$'),
  event_type text NOT NULL CHECK (event_type IN ('CREATED', 'VERSION_APPENDED')),
  evidence_digest char(64) NOT NULL CHECK (evidence_digest ~ '^[a-f0-9]{64}$'),
  previous_hash char(64) NOT NULL CHECK (previous_hash ~ '^[a-f0-9]{64}$'),
  event_hash char(64) NOT NULL UNIQUE CHECK (event_hash ~ '^[a-f0-9]{64}$'),
  occurred_at timestamptz NOT NULL,
  FOREIGN KEY (resource_id, resource_kind, version)
    REFERENCES protected_admin_versions(resource_id, resource_kind, version)
);

CREATE INDEX protected_admin_current_version_idx
  ON protected_admin_versions(resource_id, version DESC);
CREATE INDEX protected_admin_audit_resource_idx
  ON protected_admin_audit_events(resource_id, sequence_id);

CREATE FUNCTION reject_protected_admin_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'protected administration records are append-only';
END;
$$;

CREATE TRIGGER protected_admin_resources_append_only
BEFORE UPDATE OR DELETE ON protected_admin_resources
FOR EACH ROW EXECUTE FUNCTION reject_protected_admin_mutation();
CREATE TRIGGER protected_admin_versions_append_only
BEFORE UPDATE OR DELETE ON protected_admin_versions
FOR EACH ROW EXECUTE FUNCTION reject_protected_admin_mutation();
CREATE TRIGGER protected_admin_audit_append_only
BEFORE UPDATE OR DELETE ON protected_admin_audit_events
FOR EACH ROW EXECUTE FUNCTION reject_protected_admin_mutation();
