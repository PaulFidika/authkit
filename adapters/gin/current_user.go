package authgin

import (
	authlang "github.com/PaulFidika/authkit/lang"
	"github.com/gin-gonic/gin"
)

// CurrentUser is a unified view of the caller regardless of whether
// enrichment ran (UserContext) or only the JWT gate was applied.
//
// Fields with * may be empty if unavailable without DB enrichment.
type UserView struct {
	// Identity
	UserID          string  `json:"user_id"`
	Email           string  `json:"email"`
	Username        *string `json:"username,omitempty"`         // optional, not populated by default
	DiscordUsername *string `json:"discord_username,omitempty"` // optional
	Language        string  `json:"language"`

	// Access
	Roles        []string `json:"roles,omitempty"`
	Entitlements []string `json:"entitlements,omitempty"`

	// Meta
	Source string `json:"source"` // "userctx" | "claims" | "none"
}

// CurrentUser returns a unified user snapshot for handlers.
// Order of precedence:
//  1. UserContext (from UserContextMiddleware) → Source: "userctx"
//  2. JWT claims only (from AuthRequired/AuthOptional) → Source: "claims"
//  3. None (unauthenticated) → Source: "none"
func CurrentUser(c *gin.Context) (UserView, bool) {
	reqLang := "en"
	if v, ok := authlang.LanguageFromContext(c.Request.Context()); ok {
		reqLang = v
	}

	// Prefer enriched context if present
	if uc, ok := GetUserContext(c); ok && uc.UserID != "" {
		return UserView{
			UserID:          uc.UserID,
			Email:           uc.Email,
			Username:        nil,
			DiscordUsername: uc.DiscordUsername,
			Language:        reqLang,
			Roles:           uc.Roles,
			Entitlements:    uc.Entitlements,
			Source:          "userctx",
		}, true
	}

	// Fallback to JWT claims
	if cl, ok := ClaimsFromGin(c); ok && cl.UserID != "" {
		var du *string
		if v, ok := c.Get("auth.discord_username"); ok {
			if s, ok2 := v.(string); ok2 && s != "" {
				du = &s
			}
		}
		return UserView{
			UserID:          cl.UserID,
			Email:           cl.Email,
			Username:        nil,
			DiscordUsername: du,
			Language:        reqLang,
			Roles:           cl.Roles,
			Entitlements:    cl.Entitlements,
			Source:          "claims",
		}, true
	}

	// Unauthenticated
	return UserView{
		Language: reqLang,
		Source:   "none",
	}, false
}
