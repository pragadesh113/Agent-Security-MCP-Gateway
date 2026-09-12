CREATE TABLE trustworthy_interface_views (
  interface_id text PRIMARY KEY,
  request_id text NOT NULL REFERENCES requests(request_id),
  action_id text NOT NULL REFERENCES canonical_actions(action_id),
  decision_id text NOT NULL REFERENCES decisions(decision_id),
  coverage_event_id text NOT NULL REFERENCES coverage_events(coverage_event_id),
  policy_scope_id text NOT NULL,
  view_digest char(64) NOT NULL CHECK (view_digest ~ '^[a-f0-9]{64}$'),
  awareness_digest char(64) NOT NULL CHECK (awareness_digest ~ '^[a-f0-9]{64}$'),
  view_document jsonb NOT NULL,
  awareness_document jsonb NOT NULL,
  presented_at timestamptz NOT NULL,
  UNIQUE (request_id, decision_id)
);

CREATE INDEX trustworthy_interface_scope_time_idx
  ON trustworthy_interface_views(policy_scope_id, presented_at DESC);

CREATE TABLE approval_fatigue_events (
  event_id text PRIMARY KEY,
  interface_id text NOT NULL REFERENCES trustworthy_interface_views(interface_id),
  policy_scope_id text NOT NULL,
  event_type text NOT NULL CHECK (event_type IN (
    'PRESENTED', 'APPROVED', 'DENIED', 'EXPIRED', 'REVOKED', 'ERROR'
  )),
  decision_latency_ms bigint CHECK (decision_latency_ms IS NULL OR decision_latency_ms >= 0),
  related_attempt_count integer NOT NULL CHECK (related_attempt_count >= 0),
  occurred_at timestamptz NOT NULL
);

CREATE INDEX approval_fatigue_scope_time_idx
  ON approval_fatigue_events(policy_scope_id, occurred_at DESC);

CREATE TRIGGER trustworthy_interface_views_append_only
BEFORE UPDATE OR DELETE ON trustworthy_interface_views
FOR EACH ROW EXECUTE FUNCTION reject_coverage_mutation();

CREATE TRIGGER approval_fatigue_events_append_only
BEFORE UPDATE OR DELETE ON approval_fatigue_events
FOR EACH ROW EXECUTE FUNCTION reject_coverage_mutation();

CREATE TRIGGER recovery_records_append_only
BEFORE UPDATE OR DELETE ON recovery_records
FOR EACH ROW EXECUTE FUNCTION reject_coverage_mutation();
