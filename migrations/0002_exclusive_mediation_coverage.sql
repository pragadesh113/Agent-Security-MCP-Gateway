ALTER TABLE coverage_events
  ADD COLUMN scope_id char(64),
  ADD COLUMN server_id text,
  ADD COLUMN route_id text,
  ADD COLUMN policy_scope_id text,
  ADD COLUMN environment text,
  ADD COLUMN resource_class text,
  ADD COLUMN resource_id text,
  ADD COLUMN assessment_revision bigint,
  ADD COLUMN assurance text CHECK (assurance IN ('DISPOSABLE_TEST', 'DEPLOYMENT')),
  ADD COLUMN reason_codes text[],
  ADD COLUMN report_document jsonb,
  ADD COLUMN valid_until timestamptz;

ALTER TABLE coverage_events
  ADD CONSTRAINT coverage_events_state_v1
  CHECK (coverage IN ('ENFORCED', 'DEGRADED', 'OBSERVE_ONLY', 'UNPROTECTED')) NOT VALID;
ALTER TABLE coverage_events VALIDATE CONSTRAINT coverage_events_state_v1;

CREATE INDEX coverage_events_scope_time_idx
  ON coverage_events(scope_id, occurred_at DESC);

CREATE TABLE coverage_control_evidence (
  evidence_id text PRIMARY KEY,
  coverage_event_id text NOT NULL REFERENCES coverage_events(coverage_event_id),
  guarantee text NOT NULL,
  path_kind text NOT NULL CHECK (path_kind IN ('GATEWAY_MEDIATED', 'NATIVE', 'DIRECT')),
  verifier_id text NOT NULL,
  authority text NOT NULL,
  verifier_class text NOT NULL CHECK (verifier_class IN (
    'GATEWAY_SELF_CHECK', 'INDEPENDENT_CONTROL', 'TEST_FIXTURE'
  )),
  assurance text NOT NULL CHECK (assurance IN ('DISPOSABLE_TEST', 'DEPLOYMENT')),
  status text NOT NULL CHECK (status IN (
    'VERIFIED_ENFORCING', 'VERIFIED_BLOCKED', 'OBSERVE_ONLY',
    'REACHABLE', 'BROKEN', 'UNKNOWN'
  )),
  revision bigint NOT NULL CHECK (revision > 0),
  proof_digest char(64) NOT NULL CHECK (proof_digest ~ '^[a-f0-9]{64}$'),
  observed_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL CHECK (expires_at > observed_at),
  UNIQUE (coverage_event_id, path_kind, guarantee)
);

CREATE FUNCTION reject_coverage_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'coverage evidence is append-only';
END;
$$;

CREATE TRIGGER coverage_events_append_only
BEFORE UPDATE OR DELETE ON coverage_events
FOR EACH ROW EXECUTE FUNCTION reject_coverage_mutation();

CREATE TRIGGER coverage_control_evidence_append_only
BEFORE UPDATE OR DELETE ON coverage_control_evidence
FOR EACH ROW EXECUTE FUNCTION reject_coverage_mutation();
