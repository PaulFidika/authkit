package core

import (
	"context"
)

// AuthEventLogger records authentication events to an external sink (e.g., ClickHouse).
// Implementations should be non-blocking and best-effort.
type AuthEventLogger interface {
	LogLogin(ctx context.Context, userID string, issuer string, method string, sessionID string, ip *string, userAgent *string) error
}
