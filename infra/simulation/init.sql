-- Disposable simulated-production fixtures only. Never point this service at real
-- production data or credentials.

CREATE TABLE IF NOT EXISTS public.customers (
  id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  display_name text NOT NULL,
  email text NOT NULL,
  account_tier text NOT NULL
);

CREATE TABLE IF NOT EXISTS public.deployment_state (
  service_name text PRIMARY KEY,
  release_version text NOT NULL,
  status text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO public.customers (id, display_name, email, account_tier)
OVERRIDING SYSTEM VALUE
VALUES
  (1, 'Demo Customer A', 'customer-a@example.invalid', 'enterprise'),
  (2, 'Demo Customer B', 'customer-b@example.invalid', 'standard'),
  (3, 'Demo Customer C', 'customer-c@example.invalid', 'enterprise')
ON CONFLICT (id) DO UPDATE SET
  display_name = EXCLUDED.display_name,
  email = EXCLUDED.email,
  account_tier = EXCLUDED.account_tier;

SELECT setval(pg_get_serial_sequence('public.customers', 'id'), 3, true);

INSERT INTO public.deployment_state (
  service_name,
  release_version,
  status,
  updated_at
)
VALUES (
  'simulated-api',
  '2026.08-demo',
  'healthy',
  '2026-08-26T08:18:12.231918Z'
)
ON CONFLICT (service_name) DO UPDATE SET
  release_version = EXCLUDED.release_version,
  status = EXCLUDED.status,
  updated_at = EXCLUDED.updated_at;
