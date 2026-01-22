package oidckit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"golang.org/x/oauth2"
)

// RelyingParty holds discovery-backed OIDC configuration for a provider.
type RelyingParty struct {
	issuer      string
	clientID    string
	jwksURL     string
	oauthConfig *oauth2.Config
}

type discoveryDoc struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// NewRelyingPartyOIDC discovers OIDC metadata and constructs a relying party.
func NewRelyingPartyOIDC(ctx context.Context, issuer, clientID, clientSecret, redirectURI string, scopes []string) (*RelyingParty, error) {
	trimmedIssuer := strings.TrimRight(issuer, "/")
	if trimmedIssuer == "" {
		return nil, errors.New("oidc: issuer is empty")
	}
	doc, err := discoverOIDC(ctx, trimmedIssuer)
	if err != nil {
		return nil, err
	}
	effectiveIssuer := doc.Issuer
	if effectiveIssuer == "" {
		effectiveIssuer = issuer
	}
	oauthConfig := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,
		Scopes:       scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  doc.AuthorizationEndpoint,
			TokenURL: doc.TokenEndpoint,
		},
	}
	return &RelyingParty{
		issuer:      effectiveIssuer,
		clientID:    clientID,
		jwksURL:     doc.JWKSURI,
		oauthConfig: oauthConfig,
	}, nil
}

// OAuthConfig returns the OAuth2 configuration derived from discovery.
func (rp *RelyingParty) OAuthConfig() *oauth2.Config { return rp.oauthConfig }

// Issuer returns the issuer URL associated with the relying party.
func (rp *RelyingParty) Issuer() string { return rp.issuer }

// ClientID returns the OAuth client_id for the relying party.
func (rp *RelyingParty) ClientID() string { return rp.clientID }

// KeySet fetches the current JWKS for signature verification.
func (rp *RelyingParty) KeySet(ctx context.Context) (jwk.Set, error) {
	if rp.jwksURL == "" {
		return nil, errors.New("oidc: missing jwks_uri")
	}
	return jwk.Fetch(ctx, rp.jwksURL)
}

// AuthURLOpt configures authorization URL parameters.
type AuthURLOpt = oauth2.AuthCodeOption

// WithURLParam adds an arbitrary URL parameter to the auth request.
func WithURLParam(key, value string) AuthURLOpt {
	return oauth2.SetAuthURLParam(key, value)
}

// WithCodeChallenge sets the PKCE code_challenge parameter.
func WithCodeChallenge(challenge string) AuthURLOpt {
	return oauth2.SetAuthURLParam("code_challenge", challenge)
}

// AuthURL builds an authorization URL for the given RP.
func AuthURL(state string, rpClient *RelyingParty, opts ...AuthURLOpt) string {
	return rpClient.oauthConfig.AuthCodeURL(state, opts...)
}

func discoverOIDC(ctx context.Context, issuer string) (*discoveryDoc, error) {
	discoveryURL := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("oidc: discovery failed: %s", resp.Status)
	}
	var doc discoveryDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, err
	}
	discoveredIssuer := strings.TrimRight(doc.Issuer, "/")
	if discoveredIssuer != "" && discoveredIssuer != issuer {
		return nil, fmt.Errorf("oidc: issuer mismatch: %s", doc.Issuer)
	}
	if doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" || doc.JWKSURI == "" {
		return nil, errors.New("oidc: discovery missing endpoints")
	}
	return &doc, nil
}
