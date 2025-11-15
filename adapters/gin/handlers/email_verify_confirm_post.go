package handlers

import (
	"net/http"
	"strings"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

func HandleEmailVerifyConfirmPOST(svc *core.Service, rl ginutil.RateLimiter) gin.HandlerFunc {
	type verifyConfirmReq struct {
		Code string `json:"code"`
	}
	return func(c *gin.Context) {
		if !ginutil.AllowNamed(c, rl, ginutil.RLEmailVerifyConfirm) {
			ginutil.TooMany(c)
			return
		}
		var req verifyConfirmReq
		if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Code) == "" {
			ginutil.BadRequest(c, "invalid_request")
			return
		}

		// Normalize code to uppercase (codes are case-insensitive)
		code := strings.ToUpper(strings.TrimSpace(req.Code))

		// Try pending registration first (new flow)
		userID, err := svc.ConfirmPendingRegistration(c.Request.Context(), code)
		if err == nil && userID != "" {
			// Success - pending registration confirmed and user created
			c.JSON(http.StatusOK, gin.H{"ok": true, "user_id": userID, "message": "Account created successfully. You can now log in."})
			return
		}

		// Fall back to existing email verification (for OAuth users or email changes)
		if err := svc.ConfirmEmailVerification(c.Request.Context(), code); err != nil {
			ginutil.BadRequest(c, "invalid_or_expired_code")
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	}
}
