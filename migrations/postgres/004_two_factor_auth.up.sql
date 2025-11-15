-- Two-Factor Authentication (2FA) support for admin accounts
-- Allows admins to enable email or SMS-based 2FA for additional security

-- 2FA settings per user
CREATE TABLE IF NOT EXISTS profiles.two_factor_settings (
    user_id UUID PRIMARY KEY REFERENCES profiles.users(id) ON DELETE CASCADE,
    enabled BOOLEAN NOT NULL DEFAULT false,
    method VARCHAR(10) NOT NULL DEFAULT 'email' CHECK (method IN ('email', 'sms')),
    phone_number VARCHAR(20), -- E.164 format, required if method='sms'
    backup_codes TEXT[], -- Array of hashed backup codes for account recovery
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Ensure phone_number is provided when method is 'sms'
    CONSTRAINT phone_required_for_sms CHECK (
        (method = 'sms' AND phone_number IS NOT NULL) OR
        (method = 'email')
    )
);

CREATE INDEX idx_two_factor_settings_enabled ON profiles.two_factor_settings(enabled) WHERE enabled = true;

-- 2FA verification codes (similar to phone_verifications but for login 2FA)
CREATE TABLE IF NOT EXISTS profiles.two_factor_verifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES profiles.users(id) ON DELETE CASCADE,
    code_hash VARCHAR(64) NOT NULL, -- SHA256 of the 6-digit code
    method VARCHAR(10) NOT NULL CHECK (method IN ('email', 'sms', 'backup')),
    destination VARCHAR(255) NOT NULL, -- Email or phone number where code was sent
    expires_at TIMESTAMPTZ NOT NULL,
    verified BOOLEAN NOT NULL DEFAULT false,
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_two_factor_verifications_user ON profiles.two_factor_verifications(user_id);
CREATE INDEX idx_two_factor_verifications_expires ON profiles.two_factor_verifications(expires_at);

-- Clean up expired 2FA codes (similar to cleanup for other verifications)
-- Application should periodically run: DELETE FROM profiles.two_factor_verifications WHERE expires_at < NOW()

COMMENT ON TABLE profiles.two_factor_settings IS 'Two-factor authentication settings per user (admin accounts)';
COMMENT ON TABLE profiles.two_factor_verifications IS 'Active 2FA verification codes sent during login';
COMMENT ON COLUMN profiles.two_factor_settings.method IS 'Preferred 2FA method: email or sms';
COMMENT ON COLUMN profiles.two_factor_settings.backup_codes IS 'Hashed backup codes for account recovery (10 codes)';
COMMENT ON COLUMN profiles.two_factor_verifications.method IS 'Method used for this verification: email, sms, or backup (manual code entry)';
