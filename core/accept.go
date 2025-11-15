package core

import "time"

// AcceptConfig configures verification of third-party JWTs (verify-only mode).
type AcceptConfig struct {
	Issuers    []IssuerAccept
	Skew       time.Duration
	Algorithms []string
}

// IssuerAccept describes how to accept tokens from a specific issuer.
type IssuerAccept struct {
	Issuer       string
	Audience     string // Expected audience for this service (single value)
	JWKSURL      string
	PinnedRSAPEM string // optional PEM for degraded fallback
	CacheTTL     time.Duration
	MaxStale     time.Duration
}
