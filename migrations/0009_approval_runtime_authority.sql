ALTER TABLE sessions ADD COLUMN runtime_document jsonb;

CREATE TABLE approval_runtime_payloads (
  request_id text PRIMARY KEY REFERENCES requests(request_id),
  key_id text NOT NULL,
  nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
  authentication_tag bytea NOT NULL CHECK (octet_length(authentication_tag) = 16),
  ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) > 0),
  created_at timestamptz NOT NULL
);

CREATE TRIGGER approval_runtime_payloads_append_only
BEFORE UPDATE OR DELETE ON approval_runtime_payloads
FOR EACH ROW EXECUTE FUNCTION reject_coverage_mutation();
