package entitlements

import "time"

// Entitlement represents a user's grant (e.g., premium), with optional metadata.
type Entitlement struct {
	Name      string                 `json:"name"`
	ExpiresAt *time.Time             `json:"expires_at,omitempty"`
	RevokedAt *time.Time             `json:"revoked_at,omitempty"`
	Source    string                 `json:"source,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}
