ALTER TABLE supervisor_assessments
  ADD COLUMN action_id text,
  ADD COLUMN action_hash char(64) CHECK (action_hash IS NULL OR action_hash ~ '^[a-f0-9]{64}$'),
  ADD COLUMN decision_id text,
  ADD COLUMN session_id text,
  ADD COLUMN policy_scope_id text,
  ADD COLUMN schema_digest char(64) CHECK (schema_digest IS NULL OR schema_digest ~ '^[a-f0-9]{64}$'),
  ADD COLUMN policy_version text,
  ADD COLUMN prompt_version text NOT NULL DEFAULT 'legacy',
  ADD COLUMN input_digest char(64) NOT NULL DEFAULT repeat('0', 64) CHECK (input_digest ~ '^[a-f0-9]{64}$'),
  ADD COLUMN redaction_digest char(64) NOT NULL DEFAULT repeat('0', 64) CHECK (redaction_digest ~ '^[a-f0-9]{64}$'),
  ADD COLUMN latency_ms bigint NOT NULL DEFAULT 0 CHECK (latency_ms >= 0),
  ADD COLUMN status text NOT NULL DEFAULT 'COMPLETED' CHECK (status IN (
    'COMPLETED', 'DISABLED', 'NOT_REQUIRED', 'TIMEOUT', 'INVALID_OUTPUT',
    'LOW_CONFIDENCE', 'PROVIDER_FAILURE'
  )),
  ADD COLUMN external_submission boolean NOT NULL DEFAULT false,
  ADD COLUMN fallback_used boolean NOT NULL DEFAULT false,
  ADD COLUMN failure_code text,
  ADD COLUMN reason_codes text[] NOT NULL DEFAULT '{}',
  ADD COLUMN assessment_document jsonb NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN audit_digest char(64) NOT NULL DEFAULT repeat('0', 64) CHECK (audit_digest ~ '^[a-f0-9]{64}$');

ALTER TABLE security_events DROP CONSTRAINT security_events_event_type_check;
ALTER TABLE security_events ADD CONSTRAINT security_events_event_type_check CHECK (event_type IN (
  'DECIDED', 'DENIED', 'MODIFIED', 'ALTERNATE_ROUTE', 'REPLAYED', 'BYPASS', 'APPROVED',
  'FORWARDED', 'RESULT_RECORDED', 'COMPLETED', 'FAILED', 'CANCELLED', 'TIMED_OUT',
  'UNKNOWN_OUTCOME', 'TRUST_RECORDED', 'SUPERVISOR_ASSESSED'
));

CREATE INDEX supervisor_assessments_scope_time_idx
  ON supervisor_assessments(policy_scope_id, assessed_at DESC);

CREATE FUNCTION reject_supervisor_assessment_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'supervisor assessments are append-only';
END;
$$;

CREATE TRIGGER supervisor_assessments_append_only
BEFORE UPDATE OR DELETE ON supervisor_assessments
FOR EACH ROW EXECUTE FUNCTION reject_supervisor_assessment_mutation();
