-- Drop profiles schema objects (reverse order)
DROP INDEX IF EXISTS refresh_sessions_user_active;
DROP INDEX IF EXISTS refresh_sessions_prev_hash_active;
DROP INDEX IF EXISTS refresh_sessions_current_hash_active;
DROP TABLE IF EXISTS profiles.refresh_sessions;

DROP TABLE IF EXISTS profiles.user_roles;
DROP TABLE IF EXISTS profiles.roles;

DROP INDEX IF EXISTS password_resets_user_id_idx;
DROP TABLE IF EXISTS profiles.password_resets;

DROP INDEX IF EXISTS email_verifications_user_id_idx;
DROP TABLE IF EXISTS profiles.email_verifications;

-- Sign-in history table no longer created; nothing to drop here

DROP INDEX IF EXISTS user_providers_user_id_idx;
DROP TABLE IF EXISTS profiles.user_providers;

DROP TABLE IF EXISTS profiles.user_passwords;

DROP INDEX IF EXISTS users_email_uidx;
DROP TABLE IF EXISTS profiles.users;

-- Keep schema by default (comment to drop)
-- DROP SCHEMA IF EXISTS profiles CASCADE;
