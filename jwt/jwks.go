package jwtkit

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
)

// JWK minimal fields for RSA public keys.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n"` // base64url
	E   string `json:"e"` // base64url
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

// RSAPublicToJWK converts an RSA public key to a JWK.
func RSAPublicToJWK(pub *rsa.PublicKey, kid, alg string) JWK {
	n := base64URLEncode(pub.N)
	e := base64URLEncode(big.NewInt(int64(pub.E)))
	return JWK{Kty: "RSA", Use: "sig", Kid: kid, Alg: alg, N: n, E: e}
}

// ServeJWKS writes JWKS JSON to the ResponseWriter.
func ServeJWKS(w http.ResponseWriter, r *http.Request, ks JWKS) {
	// Marshal first to compute a stable ETag and set cache headers
	b, _ := json.Marshal(ks)
	sum := sha256.Sum256(b)
	etag := "\"" + hex.EncodeToString(sum[:]) + "\""

	// Conditional GET support
	if inm := r.Header.Get("If-None-Match"); inm != "" && inm == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300, must-revalidate")
	w.Header().Set("ETag", etag)
	_, _ = w.Write(b)
}

func base64URLEncode(i *big.Int) string {
	b := i.Bytes()
	// Remove leading zeros for canonical form
	for len(b) > 0 && b[0] == 0x00 {
		b = b[1:]
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
