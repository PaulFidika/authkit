package authgin

import (
	"regexp"
	"strings"

	authlang "github.com/PaulFidika/authkit/lang"
	"github.com/gin-gonic/gin"
)

type LanguageConfig struct {
	Supported  []string
	Default    string
	QueryParam string
	CookieName string
}

func (c *LanguageConfig) defaulted() LanguageConfig {
	if c == nil {
		return LanguageConfig{
			Default:    "en",
			QueryParam: "lang",
			CookieName: "lang",
		}
	}
	out := *c
	if strings.TrimSpace(out.Default) == "" {
		out.Default = "en"
	}
	if strings.TrimSpace(out.QueryParam) == "" {
		out.QueryParam = "lang"
	}
	if strings.TrimSpace(out.CookieName) == "" {
		out.CookieName = "lang"
	}
	return out
}

var reSimpleLang = regexp.MustCompile(`^[a-z]{2}$`)

func normalizeLangCode(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return ""
	}
	if i := strings.IndexAny(s, "-_"); i >= 0 {
		s = s[:i]
	}
	if !reSimpleLang.MatchString(s) {
		return ""
	}
	return s
}

func supportedSet(supported []string) map[string]struct{} {
	if len(supported) == 0 {
		return nil
	}
	m := make(map[string]struct{}, len(supported))
	for _, s := range supported {
		if n := normalizeLangCode(s); n != "" {
			m[n] = struct{}{}
		}
	}
	return m
}

func pickFromAcceptLanguage(header string, supported map[string]struct{}) string {
	header = strings.TrimSpace(header)
	if header == "" {
		return ""
	}
	parts := strings.Split(header, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if i := strings.IndexByte(part, ';'); i >= 0 {
			part = part[:i]
		}
		lang := normalizeLangCode(part)
		if lang == "" {
			continue
		}
		if supported == nil {
			return lang
		}
		if _, ok := supported[lang]; ok {
			return lang
		}
	}
	return ""
}

func pickFromPathPrefix(path string, supported map[string]struct{}) string {
	path = strings.TrimLeft(path, "/")
	if len(path) < 3 {
		return ""
	}
	seg := path
	if i := strings.IndexByte(seg, '/'); i >= 0 {
		seg = seg[:i]
	}
	lang := normalizeLangCode(seg)
	if lang == "" {
		return ""
	}
	if supported == nil {
		return lang
	}
	if _, ok := supported[lang]; ok {
		return lang
	}
	return ""
}

// resolveRequestLanguage implements the shared language contract:
// `?lang` query param > `/:lang/` path prefix > `lang` cookie > `Accept-Language` header > default.
func resolveRequestLanguage(c *gin.Context, cfg LanguageConfig) string {
	supported := supportedSet(cfg.Supported)

	if qp := normalizeLangCode(c.Query(cfg.QueryParam)); qp != "" {
		if supported == nil {
			return qp
		}
		if _, ok := supported[qp]; ok {
			return qp
		}
	}

	if lp := pickFromPathPrefix(c.Request.URL.Path, supported); lp != "" {
		return lp
	}

	if cfg.CookieName != "" {
		if cv, err := c.Cookie(cfg.CookieName); err == nil {
			if ck := normalizeLangCode(cv); ck != "" {
				if supported == nil {
					return ck
				}
				if _, ok := supported[ck]; ok {
					return ck
				}
			}
		}
	}

	if al := pickFromAcceptLanguage(c.GetHeader("Accept-Language"), supported); al != "" {
		return al
	}

	def := normalizeLangCode(cfg.Default)
	if def != "" {
		if supported == nil {
			return def
		}
		if _, ok := supported[def]; ok {
			return def
		}
	}
	return "en"
}

// LanguageMiddleware infers request language and attaches it to the request context.
func LanguageMiddleware(cfg *LanguageConfig) gin.HandlerFunc {
	c := cfg.defaulted()
	return func(g *gin.Context) {
		lang := resolveRequestLanguage(g, c)
		g.Set("authkit.language", lang)
		g.Request = g.Request.WithContext(authlang.WithLanguage(g.Request.Context(), lang))
		g.Next()
	}
}
