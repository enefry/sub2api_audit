-- Run this script interactively with psql as a PostgreSQL administrator.
-- \password prompts securely; never place the password in this file or Git.
-- This role intentionally receives SELECT on only the two required tables.

\set ON_ERROR_STOP on

BEGIN;

CREATE ROLE sub2api_audit_reader LOGIN;

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

\password sub2api_audit_reader

-- Verification examples (run as sub2api_audit_reader):
-- SELECT id, user_id, name FROM public.api_keys LIMIT 1;  -- must succeed
-- UPDATE public.api_keys SET name = name WHERE false;     -- must fail
