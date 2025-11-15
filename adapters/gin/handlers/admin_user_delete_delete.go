package handlers

import (
	"net/http"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

func HandleAdminUserDeleteDELETE(svc *core.Service, rl ginutil.RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("user_id")
		if id == "" {
			ginutil.BadRequest(c, "invalid_request")
			return
		}
		if !ginutil.AllowNamed(c, rl, ginutil.RLAdminUserSessionsRevokeAll) {
			ginutil.TooMany(c)
			return
		}
		if err := svc.AdminDeleteUser(c.Request.Context(), id); err != nil {
			ginutil.ServerErr(c, "failed_to_delete")
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	}
}
