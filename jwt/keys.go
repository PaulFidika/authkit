package jwtkit

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

const (
	// DefaultAuthKeysPath is the default directory where External Secrets mounts auth keys
	DefaultAuthKeysPath = "/vault/auth"
)

// KeySource provides the active signer and public keys for JWKS.
type KeySource interface {
	ActiveSigner() Signer
	PublicKeys() map[string]*rsa.PublicKey
}

// StaticKeySource is a simple in-memory implementation.
type StaticKeySource struct {
	Active Signer
	Pubs   map[string]*rsa.PublicKey
}

func (s StaticKeySource) ActiveSigner() Signer                  { return s.Active }
func (s StaticKeySource) PublicKeys() map[string]*rsa.PublicKey { return s.Pubs }

// GeneratedKeySource generates and persists RSA keys (for development only).
// Keys are stored in .runtime/authkit/ and reused across restarts.
type GeneratedKeySource struct {
	signer *RSASigner
	pubs   map[string]*rsa.PublicKey
}

const (
	defaultKeysDir = ".runtime/authkit"
	privateKeyFile = "private.pem"
	keyIDFile      = "kid"
)

// NewGeneratedKeySource creates a KeySource with auto-generated RSA keys.
// First attempts to load from .runtime/authkit/, otherwise generates new keys and persists them.
// This should only be used in development environments.
func NewGeneratedKeySource() (*GeneratedKeySource, error) {
	// Try to load existing keys from disk
	if signer, pubs, ok := loadKeysFromDisk(); ok {
		return &GeneratedKeySource{signer: signer, pubs: pubs}, nil
	}

	// Generate new keys
	kid := fmt.Sprintf("dev-%d", time.Now().Unix())
	signer, err := NewRSASigner(2048, kid)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Persist to disk for next startup
	if err := persistKeysToDisk(signer, kid); err != nil {
		// Log warning but continue - we can still use in-memory keys
		fmt.Printf("Warning: failed to persist authkit dev keys: %v\n", err)
	}

	return &GeneratedKeySource{
		signer: signer,
		pubs:   map[string]*rsa.PublicKey{kid: signer.PublicKey()},
	}, nil
}

func (g *GeneratedKeySource) ActiveSigner() Signer                  { return g.signer }
func (g *GeneratedKeySource) PublicKeys() map[string]*rsa.PublicKey { return g.pubs }

// loadKeysFromDisk attempts to load persisted dev keys from .runtime/authkit/
func loadKeysFromDisk() (*RSASigner, map[string]*rsa.PublicKey, bool) {
	keyPath := filepath.Join(defaultKeysDir, privateKeyFile)
	kidPath := filepath.Join(defaultKeysDir, keyIDFile)

	// Read private key PEM
	pemBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, false
	}

	// Read key ID
	kid := "dev"
	if kidBytes, err := os.ReadFile(kidPath); err == nil {
		if k := strings.TrimSpace(string(kidBytes)); k != "" {
			kid = k
		}
	}

	// Parse the key
	signer, err := NewRSASignerFromPEM(kid, pemBytes)
	if err != nil {
		return nil, nil, false
	}

	pubs := map[string]*rsa.PublicKey{kid: signer.PublicKey()}
	return signer, pubs, true
}

// persistKeysToDisk saves generated dev keys to .runtime/authkit/ for reuse across restarts
func persistKeysToDisk(signer *RSASigner, kid string) error {
	// Create directory
	if err := os.MkdirAll(defaultKeysDir, 0700); err != nil {
		return fmt.Errorf("create keys directory: %w", err)
	}

	// Marshal private key to PEM
	privDER := x509.MarshalPKCS1PrivateKey(signer.PrivateKey())
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privDER,
	})

	// Write private key
	keyPath := filepath.Join(defaultKeysDir, privateKeyFile)
	if err := os.WriteFile(keyPath, privPEM, 0600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}

	// Write key ID
	kidPath := filepath.Join(defaultKeysDir, keyIDFile)
	if err := os.WriteFile(kidPath, []byte(kid), 0600); err != nil {
		return fmt.Errorf("write key ID: %w", err)
	}

	return nil
}

// NewAutoKeySource auto-discovers JWT keys from multiple sources with the following priority:
// 1. Environment variables (ACTIVE_KEY_ID, ACTIVE_PRIVATE_KEY_PEM, PUBLIC_KEYS) - highest priority
// 2. Filesystem /vault/auth/keys.json (External Secrets Operator in Kubernetes)
// 3. Auto-generated keys in .runtime/authkit/ (development fallback)
//
// This function is designed for use in production and development environments:
// - Production: Keys injected via External Secrets into /vault/auth/keys.json
// - Local dev with secrets: Set env vars to override filesystem
// - Local dev without secrets: Auto-generates and persists keys
//
// Returns error only if keys are explicitly provided but invalid (parsing errors).
// Returns nil error with generated keys if no keys found (development mode).
func NewAutoKeySource() (KeySource, error) {
	// Priority 1: Environment variables (for local dev overrides)
	if keySource, err := tryLoadFromEnv(); err != nil {
		return nil, fmt.Errorf("failed to load keys from environment variables: %w", err)
	} else if keySource != nil {
		return keySource, nil
	}

	// Priority 2: Filesystem /vault/auth/keys.json (production K8s with External Secrets)
	if keySource, err := tryLoadFromFilesystem(DefaultAuthKeysPath); err != nil {
		return nil, fmt.Errorf("failed to load keys from %s: %w", DefaultAuthKeysPath, err)
	} else if keySource != nil {
		return keySource, nil
	}

	// Priority 3: Auto-generate for development (lowest priority).
	// In production environments, auto-generation is disabled and an error is returned
	// so that services cannot start without explicitly provisioned keys.
	if isProdEnv() {
		return nil, fmt.Errorf("no JWT keys found in env or %s and auto-generation is disabled in production; set ACTIVE_KEY_ID/ACTIVE_PRIVATE_KEY_PEM or mount keys.json", DefaultAuthKeysPath)
	}

	keySource, err := NewGeneratedKeySource()
	if err != nil {
		return nil, fmt.Errorf("failed to generate development keys: %w", err)
	}
	return keySource, nil
}

// isProdEnv returns true if the current process appears to be running in a
// production environment based on common environment variables.
// It mirrors the ENV detection commonly used by services:
//
//	ENV, APP_ENV, or ENVIRONMENT (case-insensitive).
func isProdEnv() bool {
	env := strings.TrimSpace(os.Getenv("ENV"))
	if env == "" {
		env = strings.TrimSpace(os.Getenv("APP_ENV"))
	}
	if env == "" {
		env = strings.TrimSpace(os.Getenv("ENVIRONMENT"))
	}
	env = strings.ToLower(env)
	return env == "production" || env == "prod"
}

// tryLoadFromEnv attempts to load JWT keys from environment variables.
// Returns (nil, nil) if env vars are not set (not an error).
// Returns (nil, error) if env vars are set but invalid.
// Returns (KeySource, nil) if successfully loaded.
//
// Expected environment variables:
//
//	ACTIVE_KEY_ID - The key ID for the active signing key
//	ACTIVE_PRIVATE_KEY_PEM - PEM-encoded RSA private key
//	PUBLIC_KEYS - JSON map of key IDs to PEM-encoded public keys (optional)
//
// Example PUBLIC_KEYS format:
//
//	{"key-123": "-----BEGIN PUBLIC KEY-----\n...", "key-124": "-----BEGIN PUBLIC KEY-----\n..."}
func tryLoadFromEnv() (KeySource, error) {
	activeKeyID := strings.TrimSpace(os.Getenv("ACTIVE_KEY_ID"))
	activePrivateKeyPEM := strings.TrimSpace(os.Getenv("ACTIVE_PRIVATE_KEY_PEM"))

	// If neither is set, env vars not being used
	if activeKeyID == "" && activePrivateKeyPEM == "" {
		return nil, nil
	}

	// If one is set but not the other, that's an error
	if activeKeyID == "" {
		return nil, fmt.Errorf("ACTIVE_PRIVATE_KEY_PEM is set but ACTIVE_KEY_ID is missing")
	}
	if activePrivateKeyPEM == "" {
		return nil, fmt.Errorf("ACTIVE_KEY_ID is set but ACTIVE_PRIVATE_KEY_PEM is missing")
	}

	// Parse the private key
	signer, err := NewRSASignerFromPEM(activeKeyID, []byte(activePrivateKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("failed to parse ACTIVE_PRIVATE_KEY_PEM: %w", err)
	}

	// Start with just the active key's public key
	publicKeys := map[string]*rsa.PublicKey{
		activeKeyID: signer.PublicKey(),
	}

	// Optionally load additional public keys from PUBLIC_KEYS JSON
	publicKeysJSON := strings.TrimSpace(os.Getenv("PUBLIC_KEYS"))
	if publicKeysJSON != "" {
		var pubKeyMap map[string]string
		if err := json.Unmarshal([]byte(publicKeysJSON), &pubKeyMap); err != nil {
			return nil, fmt.Errorf("failed to parse PUBLIC_KEYS JSON: %w", err)
		}

		for kid, pemStr := range pubKeyMap {
			pub, err := jwt.ParseRSAPublicKeyFromPEM([]byte(pemStr))
			if err != nil {
				// Log warning but don't fail - just skip this key
				fmt.Printf("Warning: failed to parse public key %s from PUBLIC_KEYS: %v\n", kid, err)
				continue
			}
			publicKeys[kid] = pub
		}
	}

	return StaticKeySource{
		Active: signer,
		Pubs:   publicKeys,
	}, nil
}

// tryLoadFromFilesystem attempts to load JWT keys from /vault/auth/keys.json.
// Returns (nil, nil) if the file doesn't exist (not an error).
// Returns (nil, error) if the file exists but is invalid.
// Returns (KeySource, nil) if successfully loaded.
func tryLoadFromFilesystem(keysPath string) (KeySource, error) {
	if keysPath == "" {
		keysPath = DefaultAuthKeysPath
	}

	// Check if directory exists
	if _, err := os.Stat(keysPath); os.IsNotExist(err) {
		return nil, nil // Directory doesn't exist - not an error
	}

	// Try to read keys.json
	dataPath := filepath.Join(keysPath, "keys.json")
	data, err := os.ReadFile(dataPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // File doesn't exist - not an error
		}
		return nil, fmt.Errorf("failed to read keys.json: %w", err)
	}

	// Parse the JSON
	var keyData struct {
		ActiveKeyID         string            `json:"active_key_id"`
		ActivePrivateKeyPEM string            `json:"active_private_key_pem"`
		PublicKeys          map[string]string `json:"public_keys"`
	}
	if err := json.Unmarshal(data, &keyData); err != nil {
		return nil, fmt.Errorf("failed to parse keys.json: %w", err)
	}

	// Validate required fields
	if keyData.ActiveKeyID == "" {
		return nil, fmt.Errorf("keys.json missing active_key_id")
	}
	if keyData.ActivePrivateKeyPEM == "" {
		return nil, fmt.Errorf("keys.json missing active_private_key_pem")
	}

	// Parse the private key
	signer, err := NewRSASignerFromPEM(keyData.ActiveKeyID, []byte(keyData.ActivePrivateKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Load public keys
	publicKeys := map[string]*rsa.PublicKey{keyData.ActiveKeyID: signer.PublicKey()}
	for kid, pemStr := range keyData.PublicKeys {
		pub, err := jwt.ParseRSAPublicKeyFromPEM([]byte(pemStr))
		if err != nil {
			// Log warning but continue
			fmt.Printf("Warning: failed to parse public key %s: %v\n", kid, err)
			continue
		}
		publicKeys[kid] = pub
	}

	return StaticKeySource{
		Active: signer,
		Pubs:   publicKeys,
	}, nil
}
