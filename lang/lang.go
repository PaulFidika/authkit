package lang

import "context"

type ctxKey struct{}

// WithLanguage attaches a request language to ctx.
func WithLanguage(ctx context.Context, language string) context.Context {
	return context.WithValue(ctx, ctxKey{}, language)
}

// LanguageFromContext reads a request language from ctx.
func LanguageFromContext(ctx context.Context) (string, bool) {
	v := ctx.Value(ctxKey{})
	s, ok := v.(string)
	return s, ok && s != ""
}
