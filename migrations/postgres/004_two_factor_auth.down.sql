-- Rollback two-factor authentication support

DROP TABLE IF EXISTS profiles.two_factor_verifications;
DROP TABLE IF EXISTS profiles.two_factor_settings;
