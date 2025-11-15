-- Add phone number support for registration and authentication
-- Users can register with phone OR email, and use either for login

SET lock_timeout = '10s';
SET statement_timeout = '300s';

-- Add phone number columns to users table
ALTER TABLE profiles.users
  ADD COLUMN IF NOT EXISTS phone_number text UNIQUE,
  ADD COLUMN IF NOT EXISTS phone_verified boolean DEFAULT false;

-- Make email nullable (users can register with phone instead)
-- Existing users will have email, new phone-only users will have NULL email
ALTER TABLE profiles.users
  ALTER COLUMN email DROP NOT NULL;

-- Pending phone registrations (similar to pending_registrations for email)
CREATE TABLE IF NOT EXISTS profiles.pending_phone_registrations (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  phone_number text NOT NULL,
  username     public.citext NOT NULL,
  password_hash text NOT NULL,
  code_hash    text NOT NULL,  -- SHA256 of the 6-digit code
  created_at   timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,  -- 10 minutes (shorter than email)
  UNIQUE (code_hash)
);

-- Indexes
CREATE INDEX IF NOT EXISTS pending_phone_registrations_phone_idx ON profiles.pending_phone_registrations(phone_number);
CREATE INDEX IF NOT EXISTS pending_phone_registrations_username_idx ON profiles.pending_phone_registrations(username);
CREATE INDEX IF NOT EXISTS pending_phone_registrations_expires_at_idx ON profiles.pending_phone_registrations(expires_at);

-- Phone verification codes (for existing users adding/verifying phone)
CREATE TABLE IF NOT EXISTS profiles.phone_verifications (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      uuid REFERENCES profiles.users(id) ON DELETE CASCADE,
  phone_number text NOT NULL,
  code_hash    text NOT NULL,
  purpose      text NOT NULL,  -- 'verify_phone', 'login_2fa', 'password_reset'
  created_at   timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,  -- 10 minutes
  used_at      timestamptz,
  UNIQUE (code_hash)
);

CREATE INDEX IF NOT EXISTS phone_verifications_user_id_idx ON profiles.phone_verifications(user_id);
CREATE INDEX IF NOT EXISTS phone_verifications_phone_idx ON profiles.phone_verifications(phone_number);
CREATE INDEX IF NOT EXISTS phone_verifications_expires_at_idx ON profiles.phone_verifications(expires_at);

-- Constraint: Users must have EITHER email OR phone (or both)
-- This is enforced at the application level, not database level (for flexibility)

COMMENT ON COLUMN profiles.users.phone_number IS 'E.164 format phone number (e.g., +14155551234)';
COMMENT ON COLUMN profiles.users.phone_verified IS 'Whether the phone number has been verified via SMS code';
COMMENT ON TABLE profiles.pending_phone_registrations IS 'Temporary storage for phone+password registrations until SMS verification';
COMMENT ON TABLE profiles.phone_verifications IS 'SMS verification codes for phone verification and 2FA';
