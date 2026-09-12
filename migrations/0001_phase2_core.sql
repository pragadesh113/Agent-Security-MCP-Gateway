CREATE TABLE identities (
  identity_key text PRIMARY KEY,
  user_id text NOT NULL,
  agent_id text NOT NULL,
  host_id text NOT NULL,
  credential_id text NOT NULL,
  identity_revision bigint NOT NULL CHECK (identity_revision > 0),
  document_digest char(64) NOT NULL CHECK (document_digest ~ '^[a-f0-9]{64}$'),
  created_at timestamptz NOT NULL,
  UNIQUE (user_id, agent_id, host_id, credential_id, identity_revision)
);

CREATE TABLE clients (
  client_instance_key text PRIMARY KEY,
  client_id text NOT NULL,
  identity_key text NOT NULL REFERENCES identities(identity_key),
  document_digest char(64) NOT NULL CHECK (document_digest ~ '^[a-f0-9]{64}$'),
  created_at timestamptz NOT NULL,
  UNIQUE (client_id, identity_key)
);

CREATE TABLE sessions (
  state_namespace text PRIMARY KEY,
  transport_session_id text NOT NULL UNIQUE,
  identity_key text NOT NULL REFERENCES identities(identity_key),
  client_instance_key text NOT NULL REFERENCES clients(client_instance_key),
  status text NOT NULL CHECK (status IN ('ACTIVE', 'QUARANTINED', 'CLOSED')),
  document_digest char(64) NOT NULL CHECK (document_digest ~ '^[a-f0-9]{64}$'),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL
);

CREATE TABLE servers (
  server_id text PRIMARY KEY,
  authenticated_principal_id text NOT NULL,
  credential_audience_id text NOT NULL,
  document jsonb NOT NULL,
  document_digest char(64) NOT NULL CHECK (document_digest ~ '^[a-f0-9]{64}$'),
  registered_at timestamptz NOT NULL
);

CREATE TABLE schema_versions (
  schema_digest char(64) PRIMARY KEY CHECK (schema_digest ~ '^[a-f0-9]{64}$'),
  input_schema jsonb NOT NULL,
  output_schema jsonb,
  document_digest char(64) NOT NULL CHECK (document_digest ~ '^[a-f0-9]{64}$'),
  registered_at timestamptz NOT NULL
);

CREATE TABLE routes (
  route_id text PRIMARY KEY,
  server_id text NOT NULL REFERENCES servers(server_id),
  schema_digest char(64) NOT NULL REFERENCES schema_versions(schema_digest),
  tool_name text NOT NULL,
  policy_scope_id text NOT NULL,
  environment text NOT NULL CHECK (environment IN ('DEVELOPMENT', 'TEST', 'STAGING', 'PRODUCTION', 'UNKNOWN')),
  document jsonb NOT NULL,
  document_digest char(64) NOT NULL CHECK (document_digest ~ '^[a-f0-9]{64}$'),
  registered_at timestamptz NOT NULL,
  UNIQUE (server_id, tool_name, schema_digest)
);

CREATE TABLE policies (
  policy_version text PRIMARY KEY,
  policy_digest char(64) NOT NULL CHECK (policy_digest ~ '^[a-f0-9]{64}$'),
  activated_at timestamptz NOT NULL
);

CREATE TABLE requests (
  request_id text PRIMARY KEY,
  protocol_request_id text NOT NULL,
  state_namespace text NOT NULL REFERENCES sessions(state_namespace),
  route_id text NOT NULL REFERENCES routes(route_id),
  schema_digest char(64) NOT NULL REFERENCES schema_versions(schema_digest),
  arguments_digest char(64) NOT NULL CHECK (arguments_digest ~ '^[a-f0-9]{64}$'),
  payload_bytes bigint NOT NULL CHECK (payload_bytes >= 0),
  nonce text NOT NULL,
  call_chain_id text NOT NULL,
  requested_at timestamptz NOT NULL,
  UNIQUE (state_namespace, nonce),
  UNIQUE (state_namespace, protocol_request_id)
);

CREATE TABLE canonical_actions (
  action_id text PRIMARY KEY,
  request_id text NOT NULL UNIQUE REFERENCES requests(request_id),
  action_hash char(64) NOT NULL UNIQUE CHECK (action_hash ~ '^[a-f0-9]{64}$'),
  resources_digest char(64) NOT NULL CHECK (resources_digest ~ '^[a-f0-9]{64}$'),
  data_flow_digest char(64) NOT NULL CHECK (data_flow_digest ~ '^[a-f0-9]{64}$'),
  effect text NOT NULL,
  environment text NOT NULL,
  redacted_document jsonb NOT NULL,
  created_at timestamptz NOT NULL
);

CREATE TABLE decisions (
  decision_id text PRIMARY KEY,
  request_id text NOT NULL UNIQUE REFERENCES requests(request_id),
  action_id text NOT NULL UNIQUE REFERENCES canonical_actions(action_id),
  policy_version text NOT NULL REFERENCES policies(policy_version),
  decision text NOT NULL CHECK (decision IN ('DENY', 'REQUIRE_APPROVAL', 'SANDBOX', 'ALLOW_WITH_CONSTRAINTS', 'ALLOW')),
  tier smallint NOT NULL CHECK (tier BETWEEN 0 AND 3),
  coverage text NOT NULL CHECK (coverage IN ('ENFORCED', 'DEGRADED', 'OBSERVE_ONLY', 'UNPROTECTED')),
  redacted_document jsonb NOT NULL,
  decided_at timestamptz NOT NULL
);

CREATE TABLE decision_reasons (
  decision_id text NOT NULL REFERENCES decisions(decision_id),
  position integer NOT NULL CHECK (position >= 0),
  reason_code text NOT NULL,
  PRIMARY KEY (decision_id, position),
  UNIQUE (decision_id, reason_code)
);

CREATE TABLE approvals (
  approval_id text PRIMARY KEY,
  decision_id text NOT NULL UNIQUE REFERENCES decisions(decision_id),
  request_id text NOT NULL REFERENCES requests(request_id),
  action_id text NOT NULL REFERENCES canonical_actions(action_id),
  state text NOT NULL CHECK (state IN ('PENDING', 'APPROVED', 'DENIED', 'EXPIRED', 'CONSUMED', 'REVOKED')),
  action_hash char(64) NOT NULL CHECK (action_hash ~ '^[a-f0-9]{64}$'),
  policy_version text NOT NULL REFERENCES policies(policy_version),
  requested_at timestamptz NOT NULL,
  decided_at timestamptz,
  expires_at timestamptz NOT NULL,
  decided_by_human_id text,
  consumption_id text UNIQUE,
  consumed_at timestamptz,
  forwarding_attempt_id text UNIQUE,
  redacted_document jsonb NOT NULL,
  CHECK (expires_at > requested_at AND expires_at <= requested_at + interval '5 minutes'),
  CHECK ((state = 'CONSUMED') = (consumption_id IS NOT NULL AND consumed_at IS NOT NULL AND forwarding_attempt_id IS NOT NULL)),
  CHECK (consumed_at IS NULL OR consumed_at <= expires_at)
);

CREATE TABLE forwarding_attempts (
  forwarding_attempt_id text PRIMARY KEY,
  request_id text NOT NULL REFERENCES requests(request_id),
  action_id text NOT NULL REFERENCES canonical_actions(action_id),
  decision_id text NOT NULL REFERENCES decisions(decision_id),
  approval_id text UNIQUE REFERENCES approvals(approval_id),
  route_id text NOT NULL REFERENCES routes(route_id),
  state text NOT NULL CHECK (state IN ('AUTHORIZED', 'FORWARDING', 'FORWARDED', 'COMPLETED', 'FAILED', 'CANCELLED', 'TIMED_OUT', 'UNKNOWN')),
  authorization_digest char(64) NOT NULL CHECK (authorization_digest ~ '^[a-f0-9]{64}$'),
  authorized_at timestamptz NOT NULL,
  forwarding_started_at timestamptz,
  finished_at timestamptz,
  UNIQUE (request_id)
);

CREATE TABLE result_provenance (
  provenance_id text PRIMARY KEY,
  request_id text NOT NULL REFERENCES requests(request_id),
  forwarding_attempt_id text NOT NULL UNIQUE REFERENCES forwarding_attempts(forwarding_attempt_id),
  server_id text NOT NULL REFERENCES servers(server_id),
  route_id text NOT NULL REFERENCES routes(route_id),
  schema_digest char(64) NOT NULL REFERENCES schema_versions(schema_digest),
  call_chain_id text NOT NULL,
  authenticated_principal_id text NOT NULL,
  transport_evidence_digest char(64) NOT NULL CHECK (transport_evidence_digest ~ '^[a-f0-9]{64}$'),
  received_at timestamptz NOT NULL
);

CREATE TABLE results (
  result_id text PRIMARY KEY,
  provenance_id text NOT NULL UNIQUE REFERENCES result_provenance(provenance_id),
  request_id text NOT NULL UNIQUE REFERENCES requests(request_id),
  action_id text NOT NULL REFERENCES canonical_actions(action_id),
  disposition text NOT NULL CHECK (disposition IN ('ALLOW', 'REDACT', 'DENY', 'QUARANTINE')),
  schema_validation text NOT NULL CHECK (schema_validation IN ('VALID', 'INVALID', 'UNVERIFIED')),
  content_digest char(64) NOT NULL CHECK (content_digest ~ '^[a-f0-9]{64}$'),
  byte_length bigint NOT NULL CHECK (byte_length >= 0),
  redacted_metadata jsonb NOT NULL,
  processed_at timestamptz NOT NULL
);

CREATE TABLE outcomes (
  outcome_id text PRIMARY KEY,
  request_id text NOT NULL UNIQUE REFERENCES requests(request_id),
  action_id text NOT NULL REFERENCES canonical_actions(action_id),
  decision_id text NOT NULL REFERENCES decisions(decision_id),
  approval_id text REFERENCES approvals(approval_id),
  forwarding_attempt_id text UNIQUE REFERENCES forwarding_attempts(forwarding_attempt_id),
  result_id text UNIQUE REFERENCES results(result_id),
  provenance_id text UNIQUE REFERENCES result_provenance(provenance_id),
  status text NOT NULL CHECK (status IN ('NOT_FORWARDED', 'FORWARDED', 'COMPLETED', 'FAILED', 'CANCELLED', 'TIMED_OUT', 'UNKNOWN')),
  possible_partial_effects boolean NOT NULL,
  recovery_class text NOT NULL,
  trust_evidence_eligible boolean NOT NULL,
  observed_at timestamptz NOT NULL,
  CHECK (NOT trust_evidence_eligible OR status = 'COMPLETED')
);

CREATE TABLE security_events (
  sequence_id bigserial PRIMARY KEY,
  event_id text NOT NULL UNIQUE,
  event_type text NOT NULL CHECK (event_type IN ('DECIDED', 'DENIED', 'MODIFIED', 'ALTERNATE_ROUTE', 'REPLAYED', 'BYPASS', 'APPROVED', 'FORWARDED', 'RESULT_RECORDED', 'COMPLETED', 'FAILED', 'CANCELLED', 'TIMED_OUT', 'UNKNOWN_OUTCOME', 'TRUST_RECORDED')),
  request_id text,
  state_namespace text,
  forwarding_attempt_id text,
  actor_id text NOT NULL,
  reason_codes text[] NOT NULL,
  evidence_digest char(64) NOT NULL CHECK (evidence_digest ~ '^[a-f0-9]{64}$'),
  previous_hash char(64) NOT NULL CHECK (previous_hash ~ '^[a-f0-9]{64}$'),
  event_hash char(64) NOT NULL UNIQUE CHECK (event_hash ~ '^[a-f0-9]{64}$'),
  occurred_at timestamptz NOT NULL
);

CREATE TABLE trust_evidence (
  trust_evidence_id text PRIMARY KEY,
  outcome_id text NOT NULL UNIQUE REFERENCES outcomes(outcome_id),
  state_namespace text NOT NULL REFERENCES sessions(state_namespace),
  policy_scope_id text NOT NULL,
  evidence_digest char(64) NOT NULL CHECK (evidence_digest ~ '^[a-f0-9]{64}$'),
  eligible boolean NOT NULL,
  mode text NOT NULL CHECK (mode = 'SHADOW'),
  recorded_at timestamptz NOT NULL
);

CREATE TABLE coverage_events (
  coverage_event_id text PRIMARY KEY,
  state_namespace text REFERENCES sessions(state_namespace),
  coverage text NOT NULL,
  evidence_digest char(64) NOT NULL CHECK (evidence_digest ~ '^[a-f0-9]{64}$'),
  occurred_at timestamptz NOT NULL
);

CREATE TABLE protocol_violations (
  violation_id text PRIMARY KEY,
  request_id text,
  state_namespace text,
  reason_code text NOT NULL,
  evidence_digest char(64) NOT NULL CHECK (evidence_digest ~ '^[a-f0-9]{64}$'),
  occurred_at timestamptz NOT NULL
);

CREATE TABLE supervisor_assessments (
  assessment_id text PRIMARY KEY,
  request_id text NOT NULL REFERENCES requests(request_id),
  provider_id text NOT NULL,
  model_id text NOT NULL,
  response_digest char(64) NOT NULL CHECK (response_digest ~ '^[a-f0-9]{64}$'),
  advisory_only boolean NOT NULL CHECK (advisory_only),
  assessed_at timestamptz NOT NULL
);

CREATE TABLE recovery_records (
  recovery_id text PRIMARY KEY,
  outcome_id text NOT NULL REFERENCES outcomes(outcome_id),
  recovery_class text NOT NULL,
  evidence_digest char(64) NOT NULL CHECK (evidence_digest ~ '^[a-f0-9]{64}$'),
  recorded_at timestamptz NOT NULL
);

CREATE INDEX clients_identity_idx ON clients(identity_key);
CREATE INDEX sessions_identity_idx ON sessions(identity_key, status);
CREATE INDEX routes_scope_idx ON routes(policy_scope_id, environment, tool_name);
CREATE INDEX requests_session_time_idx ON requests(state_namespace, requested_at);
CREATE INDEX decisions_policy_time_idx ON decisions(policy_version, decided_at);
CREATE INDEX approvals_state_expiry_idx ON approvals(state, expires_at);
CREATE INDEX forwarding_state_time_idx ON forwarding_attempts(state, authorized_at);
CREATE INDEX results_disposition_time_idx ON results(disposition, processed_at);
CREATE INDEX outcomes_status_time_idx ON outcomes(status, observed_at);
CREATE INDEX security_events_request_idx ON security_events(request_id, sequence_id);
CREATE INDEX security_events_session_idx ON security_events(state_namespace, sequence_id);
CREATE INDEX trust_evidence_scope_idx ON trust_evidence(policy_scope_id, recorded_at);

CREATE FUNCTION reject_security_event_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'security_events is append-only';
END;
$$;

CREATE TRIGGER security_events_append_only
BEFORE UPDATE OR DELETE ON security_events
FOR EACH ROW EXECUTE FUNCTION reject_security_event_mutation();
