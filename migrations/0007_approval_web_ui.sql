ALTER TABLE approvals ADD COLUMN policy_scope_id text
  GENERATED ALWAYS AS (redacted_document->'route'->>'policyScopeId') STORED;
ALTER TABLE approvals ADD COLUMN session_id text
  GENERATED ALWAYS AS (redacted_document->>'sessionId') STORED;
ALTER TABLE approvals ADD COLUMN state_revision bigint NOT NULL DEFAULT 1 CHECK (state_revision > 0);
ALTER TABLE approvals ADD COLUMN updated_at timestamptz NOT NULL DEFAULT clock_timestamp();

ALTER TABLE approvals ALTER COLUMN policy_scope_id SET NOT NULL;
ALTER TABLE approvals ALTER COLUMN session_id SET NOT NULL;

CREATE INDEX approvals_scope_state_time_idx
  ON approvals(policy_scope_id, state, requested_at DESC, approval_id DESC);
CREATE INDEX approvals_session_state_idx ON approvals(session_id, state);

CREATE FUNCTION enforce_approval_state_transition() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  NEW.state_revision := OLD.state_revision + 1;
  NEW.updated_at := clock_timestamp();
  IF NOT (
    (OLD.state = 'PENDING' AND NEW.state IN ('APPROVED', 'DENIED', 'EXPIRED', 'REVOKED')) OR
    (OLD.state = 'APPROVED' AND NEW.state IN ('CONSUMED', 'EXPIRED', 'REVOKED'))
  ) THEN
    RAISE EXCEPTION 'invalid approval state transition';
  END IF;
  IF NEW.approval_id <> OLD.approval_id OR NEW.decision_id <> OLD.decision_id OR
     NEW.request_id <> OLD.request_id OR NEW.action_id <> OLD.action_id OR
     NEW.action_hash <> OLD.action_hash OR NEW.policy_version <> OLD.policy_version OR
     NEW.requested_at <> OLD.requested_at OR NEW.expires_at <> OLD.expires_at OR
     (NEW.redacted_document - 'state' - 'decidedAt' - 'decidedByHumanId' - 'consumption') <>
       (OLD.redacted_document - 'state' - 'decidedAt' - 'decidedByHumanId' - 'consumption') THEN
    RAISE EXCEPTION 'approval binding is immutable';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER approvals_state_machine
BEFORE UPDATE ON approvals
FOR EACH ROW EXECUTE FUNCTION enforce_approval_state_transition();

CREATE TABLE approval_ui_humans (
  human_id text PRIMARY KEY,
  subject_digest char(64) NOT NULL UNIQUE CHECK (subject_digest ~ '^[a-f0-9]{64}$'),
  authentication_method text NOT NULL CHECK (authentication_method IN ('MUTUAL_TLS', 'OIDC', 'HARDWARE_ASSERTION')),
  authentication_revision bigint NOT NULL CHECK (authentication_revision > 0),
  active boolean NOT NULL,
  record_digest char(64) NOT NULL CHECK (record_digest ~ '^[a-f0-9]{64}$'),
  configured_at timestamptz NOT NULL
);

CREATE TABLE approval_ui_scope_grants (
  human_id text NOT NULL REFERENCES approval_ui_humans(human_id),
  policy_scope_id text NOT NULL,
  active boolean NOT NULL,
  grant_revision bigint NOT NULL CHECK (grant_revision > 0),
  grant_digest char(64) NOT NULL CHECK (grant_digest ~ '^[a-f0-9]{64}$'),
  configured_at timestamptz NOT NULL,
  PRIMARY KEY (human_id, policy_scope_id)
);

CREATE TABLE approval_ui_sessions (
  session_digest char(64) PRIMARY KEY CHECK (session_digest ~ '^[a-f0-9]{64}$'),
  human_id text NOT NULL REFERENCES approval_ui_humans(human_id),
  authentication_revision bigint NOT NULL CHECK (authentication_revision > 0),
  csrf_digest char(64) NOT NULL CHECK (csrf_digest ~ '^[a-f0-9]{64}$'),
  created_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  CHECK (expires_at > created_at),
  CHECK (last_seen_at >= created_at AND last_seen_at <= expires_at)
);

CREATE INDEX approval_ui_sessions_human_expiry_idx
  ON approval_ui_sessions(human_id, expires_at) WHERE revoked_at IS NULL;

CREATE TABLE approval_ui_security_events (
  sequence_id bigserial PRIMARY KEY,
  event_id text NOT NULL UNIQUE,
  event_type text NOT NULL CHECK (event_type IN ('HUMAN_CONFIGURED', 'SESSION_CREATED', 'DECISION_RECORDED', 'DECISION_REJECTED')),
  human_id text NOT NULL,
  approval_id text,
  policy_scope_id text,
  reason_codes text[] NOT NULL,
  evidence_digest char(64) NOT NULL CHECK (evidence_digest ~ '^[a-f0-9]{64}$'),
  previous_hash char(64) NOT NULL CHECK (previous_hash ~ '^[a-f0-9]{64}$'),
  event_hash char(64) NOT NULL UNIQUE CHECK (event_hash ~ '^[a-f0-9]{64}$'),
  occurred_at timestamptz NOT NULL
);

CREATE INDEX approval_ui_security_events_approval_idx
  ON approval_ui_security_events(approval_id, sequence_id);

CREATE TRIGGER approval_ui_humans_append_only
BEFORE DELETE ON approval_ui_humans FOR EACH ROW EXECUTE FUNCTION reject_coverage_mutation();
CREATE TRIGGER approval_ui_scope_grants_append_only
BEFORE DELETE ON approval_ui_scope_grants FOR EACH ROW EXECUTE FUNCTION reject_coverage_mutation();
CREATE TRIGGER approval_ui_security_events_append_only
BEFORE UPDATE OR DELETE ON approval_ui_security_events FOR EACH ROW EXECUTE FUNCTION reject_coverage_mutation();
