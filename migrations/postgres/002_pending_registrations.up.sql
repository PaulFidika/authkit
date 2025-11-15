-- Add pending_registrations table for unverified email/password signups
-- This prevents username/email squatting by unverified users

SET lock_timeout = '10s';
SET statement_timeout = '300s';

-- Pending registrations table (temporary storage until email verified)
CREATE TABLE IF NOT EXISTS profiles.pending_registrations (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email        public.citext NOT NULL,
  username     public.citext NOT NULL,
  password_hash text NOT NULL,
  token_hash   text NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,
  UNIQUE (token_hash)
);

-- Indexes for duplicate detection and cleanup
CREATE INDEX IF NOT EXISTS pending_registrations_email_idx ON profiles.pending_registrations(email);
CREATE INDEX IF NOT EXISTS pending_registrations_username_idx ON profiles.pending_registrations(username);
CREATE INDEX IF NOT EXISTS pending_registrations_expires_at_idx ON profiles.pending_registrations(expires_at);

-- Note: email_verifications table is no longer used for password-based registrations
-- It's still used for email change verification and OAuth user email updates
