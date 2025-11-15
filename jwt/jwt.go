package jwtkit

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

// ClaimsBuilder builds custom claims layered on top of RegisteredClaims.
type ClaimsBuilder interface {
	// Build returns application-specific claims to embed.
	Build(ctx context.Context, userID string, base jwt.RegisteredClaims) (map[string]any, error)
}

// Signer issues and verifies asymmetric JWTs.
type Signer interface {
	// Algorithm returns the JWS algorithm (e.g., RS256, EdDSA).
	Algorithm() string
	// KID returns current key id.
	KID() string
	// Sign creates a signed JWT with provided claims.
	Sign(ctx context.Context, claims jwt.MapClaims) (token string, err error)
}

// Minimal in-memory RSA signer for bootstrap/dev. Production should load from KMS or DB.
type RSASigner struct {
	key *rsa.PrivateKey
	kid string
}

func NewRSASigner(bits int, kid string) (*RSASigner, error) {
	if bits == 0 {
		bits = 2048
	}
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return &RSASigner{key: k, kid: kid}, nil
}

func (s *RSASigner) Algorithm() string           { return jwt.SigningMethodRS256.Alg() }
func (s *RSASigner) KID() string                 { return s.kid }
func (s *RSASigner) PublicKey() *rsa.PublicKey   { return &s.key.PublicKey }
func (s *RSASigner) PrivateKey() *rsa.PrivateKey { return s.key }

func (s *RSASigner) Sign(_ context.Context, claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.kid
	return token.SignedString(s.key)
}

// NewRSASignerFromPEM constructs an RSASigner from a PEM-encoded private key.
func NewRSASignerFromPEM(kid string, pemBytes []byte) (*RSASigner, error) {
	if len(pemBytes) == 0 {
		return nil, errors.New("empty RSA private key pem")
	}
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return nil, errors.New("failed to decode RSA private key pem")
	}
	var parsed *rsa.PrivateKey
	var err error
	switch blk.Type {
	case "RSA PRIVATE KEY":
		parsed, err = x509.ParsePKCS1PrivateKey(blk.Bytes)
	default:
		var key any
		key, err = x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err == nil {
			var ok bool
			if parsed, ok = key.(*rsa.PrivateKey); !ok {
				err = errors.New("pkcs8 key is not RSA private key")
			}
		}
	}
	if err != nil {
		return nil, err
	}
	return &RSASigner{key: parsed, kid: kid}, nil
}

// Helper to make base registered claims.
func BaseRegisteredClaims(subject string, audiences []string, ttl time.Duration) jwt.RegisteredClaims {
	now := time.Now()
	return jwt.RegisteredClaims{
		Subject:   subject,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		Audience:  audiences,
	}
}
