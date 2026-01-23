package authgin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	core "github.com/PaulFidika/authkit/core"
	jwtkit "github.com/PaulFidika/authkit/jwt"
	authlang "github.com/PaulFidika/authkit/lang"
	"github.com/gin-gonic/gin"
)

func TestResolveRequestLanguage_Precedence(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := LanguageConfig{
		Supported:  []string{"en", "es", "fr"},
		Default:    "en",
		QueryParam: "lang",
		CookieName: "lang",
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/fr/auth/register?lang=es", nil)
	req.Header.Set("Accept-Language", "fr-FR,fr;q=0.9,en;q=0.8")
	req.AddCookie(&http.Cookie{Name: "lang", Value: "en"})
	c.Request = req

	got := resolveRequestLanguage(c, cfg)
	if got != "es" {
		t.Fatalf("expected query param to win (es), got %q", got)
	}
}

func TestResolveRequestLanguage_SupportedEnforced(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := LanguageConfig{
		Supported:  []string{"en", "es"},
		Default:    "en",
		QueryParam: "lang",
		CookieName: "lang",
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/fr/auth/register?lang=fr", nil)
	req.Header.Set("Accept-Language", "fr-FR,fr;q=0.9,es;q=0.8")
	req.AddCookie(&http.Cookie{Name: "lang", Value: "fr"})
	c.Request = req

	got := resolveRequestLanguage(c, cfg)
	if got != "es" {
		t.Fatalf("expected unsupported inputs ignored and accept-language supported picked (es), got %q", got)
	}
}

type captureEmailSender struct {
	t    *testing.T
	seen []string
}

func (s *captureEmailSender) SendPasswordResetCode(ctx context.Context, email, username, code string) error {
	s.t.Helper()
	if l, ok := authlang.LanguageFromContext(ctx); ok {
		s.seen = append(s.seen, l)
	} else {
		s.seen = append(s.seen, "")
	}
	return nil
}
func (s *captureEmailSender) SendEmailVerificationCode(ctx context.Context, email, username, code string) error {
	s.t.Helper()
	if l, ok := authlang.LanguageFromContext(ctx); ok {
		s.seen = append(s.seen, l)
	} else {
		s.seen = append(s.seen, "")
	}
	return nil
}
func (s *captureEmailSender) SendLoginCode(ctx context.Context, email, username, code string) error {
	s.t.Helper()
	if l, ok := authlang.LanguageFromContext(ctx); ok {
		s.seen = append(s.seen, l)
	} else {
		s.seen = append(s.seen, "")
	}
	return nil
}
func (s *captureEmailSender) SendWelcome(ctx context.Context, email, username string) error {
	s.t.Helper()
	if l, ok := authlang.LanguageFromContext(ctx); ok {
		s.seen = append(s.seen, l)
	} else {
		s.seen = append(s.seen, "")
	}
	return nil
}

type captureSMSSender struct {
	t    *testing.T
	seen []string
}

func (s *captureSMSSender) SendVerificationCode(ctx context.Context, phone, code string) error {
	s.t.Helper()
	if l, ok := authlang.LanguageFromContext(ctx); ok {
		s.seen = append(s.seen, l)
	} else {
		s.seen = append(s.seen, "")
	}
	return nil
}
func (s *captureSMSSender) SendLoginCode(ctx context.Context, phone, code string) error {
	s.t.Helper()
	if l, ok := authlang.LanguageFromContext(ctx); ok {
		s.seen = append(s.seen, l)
	} else {
		s.seen = append(s.seen, "")
	}
	return nil
}

func TestLanguageMiddleware_PropagatesToSenders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	keys, err := jwtkit.NewGeneratedKeySource()
	if err != nil {
		t.Fatalf("NewGeneratedKeySource: %v", err)
	}
	cfg := core.Config{
		Issuer:          "test",
		IssuedAudiences: []string{"test"},
		ExpectedAudiences: []string{
			"test",
		},
		Keys: keys,
	}

	svc, err := NewService(cfg)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	es := &captureEmailSender{t: t}
	ss := &captureSMSSender{t: t}

	r := gin.New()
	svc.WithEmailSender(es).
		WithSMSSender(ss).
		WithLanguageConfig(LanguageConfig{Supported: []string{"en", "es"}, Default: "en"}).
		GinRegisterAPI(r)

	body, _ := json.Marshal(map[string]any{
		"identifier": "user@example.com",
		"username":   "user1",
		"password":   "Password123!",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/register?lang=es", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", w.Code, w.Body.String())
	}
	if len(es.seen) == 0 || es.seen[len(es.seen)-1] != "es" {
		t.Fatalf("expected email sender to see language es, got %#v", es.seen)
	}

	body2, _ := json.Marshal(map[string]any{
		"identifier": "+15555550123",
		"username":   "user2",
		"password":   "Password123!",
	})
	req2 := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(body2))
	req2.Header.Set("Content-Type", "application/json")
	req2.AddCookie(&http.Cookie{Name: "lang", Value: "es"})
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", w2.Code, w2.Body.String())
	}
	if len(ss.seen) == 0 || ss.seen[len(ss.seen)-1] != "es" {
		t.Fatalf("expected sms sender to see language es, got %#v", ss.seen)
	}
}

func TestCurrentUser_UsesRequestLanguageFromContext(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Unauthenticated: should still return request language.
	{
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest(http.MethodGet, "/auth/user/me", nil)
		req = req.WithContext(authlang.WithLanguage(req.Context(), "es"))
		c.Request = req

		u, ok := CurrentUser(c)
		if ok {
			t.Fatalf("expected ok=false for unauthenticated")
		}
		if u.Language != "es" {
			t.Fatalf("expected language es, got %q", u.Language)
		}
	}

	// Authenticated: should still return request language (independent of identity structs).
	{
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		ctx := authlang.WithLanguage(context.Background(), "es")
		ctx = SetClaims(ctx, Claims{UserID: "u_1", Email: "user@example.com"})
		req := httptest.NewRequest(http.MethodGet, "/auth/user/me", nil).WithContext(ctx)
		c.Request = req

		u, ok := CurrentUser(c)
		if !ok {
			t.Fatalf("expected ok=true for authenticated claims")
		}
		if u.Language != "es" {
			t.Fatalf("expected language es, got %q", u.Language)
		}
	}
}
