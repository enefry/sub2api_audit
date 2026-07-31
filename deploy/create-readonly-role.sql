-- Run manually as a PostgreSQL administrator after replacing the password.
-- This script intentionally grants SELECT on only the two required tables.

BEGIN;

CREATE ROLE sub2api_audit_reader
    LOGIN
    PASSWORD 'fkoIqA0SyXYsV8Q';

ALTER ROLE sub2api_audit_reader
    SET default_transaction_read_only = on;
ALTER ROLE sub2api_audit_reader
    SET statement_timeout = '2s';

GRANT CONNECT ON DATABASE sub2api TO sub2api_audit_reader;
GRANT USAGE ON SCHEMA public TO sub2api_audit_reader;
GRANT SELECT ON TABLE public.api_keys, public.users
    TO sub2api_audit_reader;

REVOKE CREATE ON SCHEMA public FROM sub2api_audit_reader;

COMMIT;

-- Verification examples (run as sub2api_audit_reader):
-- SELECT id, user_id, name FROM public.api_keys LIMIT 1;  -- must succeed
-- UPDATE public.api_keys SET name = name WHERE false;     -- must fail

