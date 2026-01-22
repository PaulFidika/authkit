package oidckit

import (
	"context"
	"fmt"

	"golang.org/x/oauth2"
)

// DefaultExchanger exchanges an authorization code using PKCE and extracts minimal claims.
func DefaultExchanger(ctx context.Context, rpClient *RelyingParty, provider, code, verifier, nonce string) (Claims, error) {
	// The RP client's built-in verifier doesn't know about our per-request nonce.
	// We need to: 1) Exchange code for tokens, 2) Manually verify ID token with custom verifier

	// Step 1: Exchange authorization code for tokens using OAuth2 directly (no ID token verification)
	oauthConfig := rpClient.OAuthConfig()

	// Add PKCE verifier to the token exchange
	var opts []oauth2.AuthCodeOption
	if provider != "apple" {
		opts = append(opts, oauth2.SetAuthURLParam("code_verifier", verifier))
	}

	oauth2Token, err := oauthConfig.Exchange(ctx, code, opts...)
	if err != nil {
		return Claims{}, fmt.Errorf("token exchange failed for %s: %w", provider, err)
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return Claims{}, fmt.Errorf("no id_token in response")
	}

	keySet, err := rpClient.KeySet(ctx)
	if err != nil {
		return Claims{}, fmt.Errorf("jwks fetch failed for %s: %w", provider, err)
	}
	customVerifier := NewIDTokenVerifier(
		rpClient.Issuer(),
		rpClient.ClientID(),
		keySet,
		WithNonce(func(context.Context) string { return nonce }),
	)

	idTokenClaims, err := VerifyIDToken(ctx, rawIDToken, customVerifier)
	if err != nil {
		return Claims{}, fmt.Errorf("id_token verification with nonce failed for %s: %w", provider, err)
	}

	idt := idTokenClaims
	if idt == nil {
		return Claims{}, fmt.Errorf("missing id_token claims")
	}
	sub := idt.GetSubject()
	// Extract common fields from claims map if present
	var email string
	var ev bool
	if idt.Email != "" {
		email = idt.Email
	}
	if idt.EmailVerified != nil {
		ev = *idt.EmailVerified
	}
	name := idt.Name
	// Try to capture preferred_username if present
	var pu *string
	if idt.PreferredUsername != "" {
		pu = &idt.PreferredUsername
	}
	return Claims{Subject: sub, Email: strptr(email), EmailVerified: boolptr(ev), Name: strptr(name), PreferredUsername: pu, RawIDToken: rawIDToken}, nil
}

func strptr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
func boolptr(b bool) *bool { return &b }
