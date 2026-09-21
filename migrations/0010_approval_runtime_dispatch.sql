CREATE TABLE approval_runtime_dispatches (
  approval_id text PRIMARY KEY REFERENCES approvals(approval_id),
  request_id text NOT NULL UNIQUE REFERENCES requests(request_id),
  human_id text NOT NULL,
  state text NOT NULL CHECK (state IN ('PENDING', 'CLAIMED', 'COMPLETED', 'FAILED')),
  claim_id text UNIQUE,
  created_at timestamptz NOT NULL,
  claimed_at timestamptz,
  finished_at timestamptz,
  failure_reason_code text,
  CHECK (
    (state = 'PENDING' AND claim_id IS NULL AND claimed_at IS NULL
      AND finished_at IS NULL AND failure_reason_code IS NULL) OR
    (state = 'CLAIMED' AND claim_id IS NOT NULL AND claimed_at IS NOT NULL
      AND finished_at IS NULL AND failure_reason_code IS NULL) OR
    (state = 'COMPLETED' AND claim_id IS NOT NULL AND claimed_at IS NOT NULL
      AND finished_at IS NOT NULL AND failure_reason_code IS NULL) OR
    (state = 'FAILED' AND finished_at IS NOT NULL AND failure_reason_code IS NOT NULL)
  )
);

CREATE INDEX approval_runtime_dispatches_recovery_idx
  ON approval_runtime_dispatches(state, COALESCE(claimed_at, created_at));

CREATE FUNCTION enforce_approval_runtime_dispatch_insert() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.state <> 'PENDING' OR NOT EXISTS (
    SELECT 1 FROM approvals a
    WHERE a.approval_id=NEW.approval_id AND a.request_id=NEW.request_id
      AND a.state='APPROVED' AND a.decided_by_human_id=NEW.human_id
  ) THEN
    RAISE EXCEPTION 'approval runtime dispatch authority is invalid';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER approval_runtime_dispatches_insert_guard
BEFORE INSERT ON approval_runtime_dispatches
FOR EACH ROW EXECUTE FUNCTION enforce_approval_runtime_dispatch_insert();

CREATE FUNCTION enforce_approval_runtime_dispatch_transition() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.approval_id <> OLD.approval_id OR NEW.request_id <> OLD.request_id OR
     NEW.human_id <> OLD.human_id OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'approval runtime dispatch binding is immutable';
  END IF;
  IF NOT (
    (OLD.state = 'PENDING' AND NEW.state IN ('CLAIMED', 'FAILED')) OR
    (OLD.state = 'CLAIMED' AND NEW.state IN ('COMPLETED', 'FAILED'))
  ) THEN
    RAISE EXCEPTION 'invalid approval runtime dispatch transition';
  END IF;
  IF OLD.state = 'PENDING' AND NEW.state = 'CLAIMED' AND
     (NEW.claim_id IS NULL OR NEW.claimed_at IS NULL) THEN
    RAISE EXCEPTION 'claimed approval runtime dispatch requires claim evidence';
  END IF;
  IF OLD.state = 'PENDING' AND NEW.state = 'FAILED' AND
     (NEW.claim_id IS NOT NULL OR NEW.claimed_at IS NOT NULL) THEN
    RAISE EXCEPTION 'unclaimed approval runtime dispatch cannot gain claim evidence';
  END IF;
  IF OLD.state = 'CLAIMED' AND
     (NEW.claim_id <> OLD.claim_id OR NEW.claimed_at <> OLD.claimed_at) THEN
    RAISE EXCEPTION 'approval runtime dispatch claim is immutable';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER approval_runtime_dispatches_state_machine
BEFORE UPDATE ON approval_runtime_dispatches
FOR EACH ROW EXECUTE FUNCTION enforce_approval_runtime_dispatch_transition();

CREATE TRIGGER approval_runtime_dispatches_no_delete
BEFORE DELETE ON approval_runtime_dispatches
FOR EACH ROW EXECUTE FUNCTION reject_coverage_mutation();
