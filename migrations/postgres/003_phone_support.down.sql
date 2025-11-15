-- Rollback phone support

DROP TABLE IF EXISTS profiles.phone_verifications;
DROP TABLE IF EXISTS profiles.pending_phone_registrations;

ALTER TABLE profiles.users DROP COLUMN IF EXISTS phone_verified;
ALTER TABLE profiles.users DROP COLUMN IF EXISTS phone_number;

-- Restore email as NOT NULL (careful - this will fail if there are phone-only users)
-- ALTER TABLE profiles.users ALTER COLUMN email SET NOT NULL;
