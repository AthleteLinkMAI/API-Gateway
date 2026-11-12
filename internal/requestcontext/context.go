package requestcontext

import "context"

type identityKey struct{}
type requestIDKey struct{}
type verifiedAccessTokenKey struct{}

type Identity struct {
	UserID string
	Role   string
}

func WithIdentity(ctx context.Context, identity Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, identity)
}

func IdentityFrom(ctx context.Context) (Identity, bool) {
	identity, ok := ctx.Value(identityKey{}).(Identity)
	return identity, ok && identity.UserID != ""
}

func WithVerifiedAccessToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, verifiedAccessTokenKey{}, token)
}

func VerifiedAccessTokenFrom(ctx context.Context) (string, bool) {
	token, ok := ctx.Value(verifiedAccessTokenKey{}).(string)
	return token, ok && token != ""
}

func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

func RequestIDFrom(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(requestIDKey{}).(string)
	return id, ok && id != ""
}

type identityHeadersKey struct{}

type IdentityHeaders struct {
	UserIDHeader string
	IncludeRole  bool
}

func WithIdentityHeaders(ctx context.Context, headers IdentityHeaders) context.Context {
	return context.WithValue(ctx, identityHeadersKey{}, headers)
}

func IdentityHeadersFrom(ctx context.Context) (IdentityHeaders, bool) {
	headers, ok := ctx.Value(identityHeadersKey{}).(IdentityHeaders)
	return headers, ok
}
