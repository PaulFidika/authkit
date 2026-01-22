package oidckit

import (
	"context"
	"errors"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// IDTokenClaims captures the minimal identity fields we extract from the ID token.
type IDTokenClaims struct {
	Subject           string
	Email             string
	EmailVerified     *bool
	Name              string
	PreferredUsername string
}

// GetSubject returns the subject claim.
func (c *IDTokenClaims) GetSubject() string { return c.Subject }

// IDTokenVerifier validates ID tokens against issuer, audience, and keys.
type IDTokenVerifier struct {
	issuer   string
	clientID string
	keySet   jwk.Set
	nonce    func(context.Context) string
}

// VerifierOpt configures an ID token verifier.
type VerifierOpt func(*IDTokenVerifier)

// WithNonce requires the token to carry the given nonce.
func WithNonce(fn func(context.Context) string) VerifierOpt {
	return func(v *IDTokenVerifier) {
		v.nonce = fn
	}
}

// NewIDTokenVerifier builds a verifier for the specified issuer and client.
func NewIDTokenVerifier(issuer, clientID string, keySet jwk.Set, opts ...VerifierOpt) *IDTokenVerifier {
	v := &IDTokenVerifier{
		issuer:   issuer,
		clientID: clientID,
		keySet:   keySet,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// VerifyIDToken validates the ID token and extracts claims.
func VerifyIDToken(ctx context.Context, rawToken string, v *IDTokenVerifier) (*IDTokenClaims, error) {
	if v == nil {
		return nil, errors.New("oidc: missing verifier")
	}
	if v.keySet == nil {
		return nil, errors.New("oidc: missing key set")
	}
	token, err := jwt.ParseString(
		rawToken,
		jwt.WithKeySet(v.keySet),
		jwt.WithValidate(true),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.clientID),
		jwt.WithContext(ctx),
	)
	if err != nil {
		return nil, err
	}
	if v.nonce != nil {
		expected := v.nonce(ctx)
		if expected != "" {
			rawNonce, ok := token.Get("nonce")
			if !ok {
				return nil, errors.New("oidc: missing nonce")
			}
			nonce, ok := rawNonce.(string)
			if !ok || nonce != expected {
				return nil, errors.New("oidc: nonce mismatch")
			}
		}
	}
	claims := &IDTokenClaims{Subject: token.Subject()}
	if rawEmail, ok := token.Get("email"); ok {
		if email, ok := rawEmail.(string); ok {
			claims.Email = email
		}
	}
	if rawVerified, ok := token.Get("email_verified"); ok {
		switch v := rawVerified.(type) {
		case bool:
			claims.EmailVerified = &v
		case string:
			if strings.EqualFold(v, "true") {
				b := true
				claims.EmailVerified = &b
			} else if strings.EqualFold(v, "false") {
				b := false
				claims.EmailVerified = &b
			}
		}
	}
	if rawName, ok := token.Get("name"); ok {
		if name, ok := rawName.(string); ok {
			claims.Name = name
		}
	}
	if rawPreferred, ok := token.Get("preferred_username"); ok {
		if preferred, ok := rawPreferred.(string); ok {
			claims.PreferredUsername = preferred
		}
	}
	return claims, nil
}
