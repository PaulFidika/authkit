-- Combined minimal authkit migrations (profiles schema)
-- All apps use admin super-user, no role management needed
-- Bootstrap creates this schema, but we keep this for safety/standalone use
SET lock_timeout = '10s';
SET statement_timeout = '300s';

-- Create citext extension for case-insensitive text in public schema
CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public;

CREATE SCHEMA IF NOT EXISTS profiles;

-- Users
CREATE TABLE IF NOT EXISTS profiles.users (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email             public.citext,
  username          public.citext UNIQUE,
  discord_username  text,
  email_verified    boolean NOT NULL DEFAULT false,
  is_active         boolean NOT NULL DEFAULT true,
  deleted_at        timestamptz,
  biography         text,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  last_login        timestamptz
);

-- Case-insensitive uniqueness via partial unique index on citext (portable across PG versions)
-- Partial index allows multiple NULL emails (e.g., OAuth users with unverified emails)
CREATE UNIQUE INDEX IF NOT EXISTS users_email_uidx ON profiles.users (email) WHERE email IS NOT NULL;

-- Passwords
CREATE TABLE IF NOT EXISTS profiles.user_passwords (
  user_id             uuid PRIMARY KEY REFERENCES profiles.users(id) ON DELETE CASCADE,
  password_hash       text NOT NULL,
  hash_algo           text NOT NULL DEFAULT 'argon2id',
  hash_params         jsonb,
  password_updated_at timestamptz NOT NULL DEFAULT now()
);

-- External providers
CREATE TABLE IF NOT EXISTS profiles.user_providers (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id           uuid NOT NULL REFERENCES profiles.users(id) ON DELETE CASCADE,
  issuer            text NOT NULL,
  provider_slug     text,
  subject           text NOT NULL,
  email_at_provider text,
  profile           jsonb,
  created_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE (issuer, subject),
  UNIQUE (user_id, issuer)
);
CREATE INDEX IF NOT EXISTS user_providers_user_id_idx ON profiles.user_providers (user_id);

-- Password resets
CREATE TABLE IF NOT EXISTS profiles.password_resets (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      uuid NOT NULL REFERENCES profiles.users(id) ON DELETE CASCADE,
  token_hash   text NOT NULL,
  requested_at timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,
  used_at      timestamptz,
  UNIQUE (token_hash)
);
CREATE INDEX IF NOT EXISTS password_resets_user_id_idx ON profiles.password_resets (user_id);
CREATE INDEX IF NOT EXISTS password_resets_expires_at_idx ON profiles.password_resets (expires_at);

-- Email verifications
CREATE TABLE IF NOT EXISTS profiles.email_verifications (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      uuid NOT NULL REFERENCES profiles.users(id) ON DELETE CASCADE,
  token_hash   text NOT NULL,
  email        public.citext NOT NULL,
  requested_at timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,
  used_at      timestamptz,
  UNIQUE (token_hash)
);
CREATE INDEX IF NOT EXISTS email_verifications_user_id_idx ON profiles.email_verifications (user_id);
CREATE INDEX IF NOT EXISTS email_verifications_expires_at_idx ON profiles.email_verifications (expires_at);

-- Sign-in history removed; login events are recorded in ClickHouse

-- Roles
CREATE TABLE IF NOT EXISTS profiles.roles (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name        text NOT NULL,
  slug        text NOT NULL UNIQUE,
  description text,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  deleted_at  timestamptz
);

CREATE TABLE IF NOT EXISTS profiles.user_roles (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    uuid NOT NULL REFERENCES profiles.users(id) ON DELETE CASCADE,
  role_id    uuid NOT NULL REFERENCES profiles.roles(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, role_id)
);

-- Refresh sessions (server-side sessions)
CREATE TABLE IF NOT EXISTS profiles.refresh_sessions (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             uuid NOT NULL REFERENCES profiles.users(id) ON DELETE CASCADE,
    issuer              text NOT NULL,
    family_id           uuid NOT NULL DEFAULT gen_random_uuid(),
    current_token_hash  bytea NOT NULL,
    previous_token_hash bytea,
    created_at          timestamptz NOT NULL DEFAULT now(),
    last_used_at        timestamptz NOT NULL DEFAULT now(),
    expires_at          timestamptz,
    revoked_at          timestamptz,
    user_agent          text,
    ip_addr             inet
);
CREATE UNIQUE INDEX IF NOT EXISTS refresh_sessions_current_hash_active
    ON profiles.refresh_sessions (current_token_hash)
    WHERE revoked_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS refresh_sessions_prev_hash_active
    ON profiles.refresh_sessions (previous_token_hash)
    WHERE revoked_at IS NULL AND previous_token_hash IS NOT NULL;
-- Avoid volatile functions in index predicate (now() is not allowed):
-- Keep the partial index on non-revoked sessions; apply expiry filter at query time.
CREATE INDEX IF NOT EXISTS refresh_sessions_user_active
    ON profiles.refresh_sessions (user_id, issuer)
    WHERE revoked_at IS NULL;

