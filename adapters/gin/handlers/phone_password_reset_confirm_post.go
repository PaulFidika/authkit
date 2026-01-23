package handlers

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	pwhash "github.com/PaulFidika/authkit/password"
	"github.com/gin-gonic/gin"
)

// HandlePhonePasswordResetConfirmPOST handles POST /auth/phone/password/reset/confirm
func HandlePhonePasswordResetConfirmPOST(svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {
	type confirmReq struct {
		PhoneNumber string `json:"phone_number"` // legacy; no longer required
		Code        string `json:"code"`         // token from reset link (legacy field name)
		NewPassword string `json:"new_password"`
	}
	return func(c *gin.Context) {
		if !ginutil.AllowNamed(c, rl, ginutil.RLPasswordResetConfirm) {
			ginutil.TooMany(c)
			return
		}

		var req confirmReq
		if err := c.ShouldBindJSON(&req); err != nil {
			ginutil.BadRequest(c, "invalid_request")
			return
		}

		phone := strings.TrimSpace(req.PhoneNumber)
		// Token is case-sensitive; do NOT normalize.
		code := strings.TrimSpace(req.Code)
		newPass := req.NewPassword

		// Legacy: if phone provided, validate format. Token-based reset does not require phone.
		if phone != "" {
			phoneRegex := regexp.MustCompile(`^\+[1-9]\d{1,14}$`)
			if !phoneRegex.MatchString(phone) {
				ginutil.BadRequest(c, "invalid_phone_number")
				return
			}
		}

		// Validate password
		if err := pwhash.Validate(newPass); err != nil {
			ginutil.BadRequest(c, "weak_password")
			return
		}

		// Verify token and reset password
		userID, err := svc.ConfirmPasswordReset(c.Request.Context(), code, newPass)
		if err != nil {
			ginutil.BadRequest(c, "invalid_or_expired_token")
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"ok":      true,
			"user_id": userID,
			"message": "Password reset successfully. You can now log in with your new password.",
		})
	}
}
