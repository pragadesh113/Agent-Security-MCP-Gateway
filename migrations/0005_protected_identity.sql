CREATE TABLE protected_client_identity_revisions (
  identity_id text NOT NULL,
  revision bigint NOT NULL CHECK (revision > 0),
  user_id text NOT NULL,
  agent_id text NOT NULL,
  client_id text NOT NULL,
  host_id text NOT NULL,
  credential_id text NOT NULL,
  fingerprint_sha256 char(64) NOT NULL CHECK (fingerprint_sha256 ~ '^[a-f0-9]{64}$'),
  status text NOT NULL CHECK (status IN ('ACTIVE', 'REVOKED')),
  valid_from timestamptz NOT NULL,
  valid_to timestamptz NOT NULL,
  record_document jsonb NOT NULL,
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (identity_id, revision),
  CHECK (valid_to > valid_from)
);

CREATE UNIQUE INDEX protected_client_identity_fingerprint_revision_idx
  ON protected_client_identity_revisions(fingerprint_sha256, identity_id, revision);

CREATE INDEX protected_client_identity_active_lookup_idx
  ON protected_client_identity_revisions(fingerprint_sha256, revision DESC)
  WHERE status = 'ACTIVE';

CREATE TABLE protected_client_identity_audit_events (
  sequence_id bigserial PRIMARY KEY,
  event_id text NOT NULL UNIQUE,
  identity_id text NOT NULL,
  revision bigint NOT NULL CHECK (revision > 0),
  event_type text NOT NULL CHECK (event_type IN ('REGISTERED', 'ROTATED', 'REVOKED')),
  actor_id text NOT NULL,
  reason_codes text[] NOT NULL DEFAULT '{}',
  evidence_digest char(64) NOT NULL CHECK (evidence_digest ~ '^[a-f0-9]{64}$'),
  previous_hash char(64) NOT NULL CHECK (previous_hash ~ '^[a-f0-9]{64}$'),
  event_hash char(64) NOT NULL UNIQUE CHECK (event_hash ~ '^[a-f0-9]{64}$'),
  occurred_at timestamptz NOT NULL,
  FOREIGN KEY (identity_id, revision)
    REFERENCES protected_client_identity_revisions(identity_id, revision)
);

CREATE INDEX protected_client_identity_audit_identity_idx
  ON protected_client_identity_audit_events(identity_id, sequence_id);

CREATE FUNCTION reject_protected_client_identity_revision_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'protected client identity revisions are append-only';
END;
$$;

CREATE TRIGGER protected_client_identity_revisions_append_only
BEFORE UPDATE OR DELETE ON protected_client_identity_revisions
FOR EACH ROW EXECUTE FUNCTION reject_protected_client_identity_revision_mutation();

CREATE FUNCTION reject_protected_client_identity_audit_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'protected client identity audit events are append-only';
END;
$$;

CREATE TRIGGER protected_client_identity_audit_append_only
BEFORE UPDATE OR DELETE ON protected_client_identity_audit_events
FOR EACH ROW EXECUTE FUNCTION reject_protected_client_identity_audit_mutation();
