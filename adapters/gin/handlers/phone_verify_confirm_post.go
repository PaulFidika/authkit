package handlers

import (
	"net/http"
	"strings"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

func HandlePhoneVerifyConfirmPOST(svc *core.Service, rl ginutil.RateLimiter) gin.HandlerFunc {
	type verifyPhoneReq struct {
		PhoneNumber string `json:"phone_number"`
		Code        string `json:"code"`
	}
	return func(c *gin.Context) {
		if !ginutil.AllowNamed(c, rl, ginutil.RLEmailVerifyConfirm) {
			ginutil.TooMany(c)
			return
		}

		var req verifyPhoneReq
		if err := c.ShouldBindJSON(&req); err != nil {
			ginutil.BadRequest(c, "invalid_request")
			return
		}

		phone := strings.TrimSpace(req.PhoneNumber)
		// Normalize code to uppercase (codes are case-insensitive alphanumeric)
		code := strings.ToUpper(strings.TrimSpace(req.Code))

		if phone == "" || code == "" {
			ginutil.BadRequest(c, "invalid_request")
			return
		}

		// Verify code and create user
		userID, err := svc.ConfirmPendingPhoneRegistration(c.Request.Context(), phone, code)
		if err != nil {
			ginutil.BadRequest(c, "invalid_or_expired_code")
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"ok":      true,
			"user_id": userID,
			"message": "Account created successfully. You can now log in.",
		})
	}
}
