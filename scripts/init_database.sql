-- Inicialização do PostgreSQL para o projeto PhishGuard
-- Execução (como utilizador postgres):
--   psql -v ON_ERROR_STOP=1 -f scripts/init_database.sql

SELECT 'CREATE ROLE phishguard_user LOGIN PASSWORD ''phishguard_password'''
WHERE NOT EXISTS (
    SELECT FROM pg_catalog.pg_roles WHERE rolname = 'phishguard_user'
)\gexec

SELECT 'CREATE DATABASE phishguard OWNER phishguard_user'
WHERE NOT EXISTS (
    SELECT FROM pg_database WHERE datname = 'phishguard'
)\gexec

GRANT ALL PRIVILEGES ON DATABASE phishguard TO phishguard_user;

\connect phishguard;

GRANT USAGE, CREATE ON SCHEMA public TO phishguard_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO phishguard_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO phishguard_user;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
GRANT ALL PRIVILEGES ON TABLES TO phishguard_user;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
GRANT ALL PRIVILEGES ON SEQUENCES TO phishguard_user;
