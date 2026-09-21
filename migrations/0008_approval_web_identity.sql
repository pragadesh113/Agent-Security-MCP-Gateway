ALTER TABLE approval_ui_humans
  DROP CONSTRAINT approval_ui_humans_authentication_method_check;

ALTER TABLE approval_ui_humans
  ADD CONSTRAINT approval_ui_humans_authentication_method_check
  CHECK (authentication_method IN ('MUTUAL_TLS', 'OIDC', 'WEBAUTHN'));
