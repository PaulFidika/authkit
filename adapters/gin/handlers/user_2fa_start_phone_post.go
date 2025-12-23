package handlers

import (
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

type start2FAPhoneRequest struct {
	Phone string `json:"phone"`
}

type start2FAPhoneResponse struct {
	Ok bool `json:"ok"`
}

// HandleUser2FAStartPhonePOST generates and sends a 6-digit code to the user's phone for 2FA setup
func HandleUser2FAStartPhonePOST(svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !ginutil.AllowNamed(c, rl, ginutil.RL2FAStartPhone) {
			ginutil.TooMany(c)
			return
		}
		var req start2FAPhoneRequest
		if err := c.ShouldBindJSON(&req); err != nil || req.Phone == "" {
			ginutil.BadRequest(c, "invalid_request")
			return
		}

		uid := c.GetString("auth.user_id")
		if uid == "" {
			ginutil.Unauthorized(c, "unauthorized")
			return
		}

		phoneNum := strings.TrimSpace(req.Phone)
		if !strings.HasPrefix(phoneNum, "+") {
			ginutil.BadRequest(c, "phone_number_must_be_e164")
			return
		}

		// Generate random 6-digit code
		rand.Seed(time.Now().UnixNano())
		code := strconv.Itoa(100000 + rand.Intn(900000))
		// Store and send code (implementation in core)
		err := svc.SendPhone2FASetupCode(c.Request.Context(), uid, req.Phone, code)
		if err != nil {
			ginutil.ServerErrWithLog(c, "send_code_failed", err, "failed to send 2fa setup code")
			return
		}
		c.JSON(http.StatusOK, start2FAPhoneResponse{Ok: true})
	}
}
