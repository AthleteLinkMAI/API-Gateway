package auth

import (
	"context"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"testing"

	"gitlab.com/team-anonyms/athelete-link/api-gateway/internal/requestcontext"
)

func TestVerifierBanlistAndDenylistPolicy(t *testing.T) {
	commandErr := errors.New("Redis command failed")
	for _, tc := range []struct {
		name                     string
		denied, banned           bool
		denyErr, banErr, wantErr error
		denyResult, banResult    string
	}{
		{name: "clear", denyResult: "clear", banResult: "clear"},
		{name: "banned", banned: true, wantErr: ErrUserBanned, denyResult: "clear", banResult: "denied"},
		{name: "revoked", denied: true, wantErr: ErrInvalidToken, denyResult: "denied", banResult: "clear"},
		{name: "both listed", denied: true, banned: true, wantErr: ErrInvalidToken, denyResult: "denied", banResult: "denied"},
		{name: "deny unavailable", denyErr: ErrRedisUnavailable, denyResult: "unavailable", banResult: "clear"},
		{name: "ban unavailable", banErr: ErrRedisUnavailable, denyResult: "clear", banResult: "unavailable"},
		{name: "both unavailable", denyErr: ErrRedisUnavailable, banErr: ErrRedisUnavailable, denyResult: "unavailable", banResult: "unavailable"},
		{name: "ban despite deny unavailable", banned: true, denyErr: ErrRedisUnavailable, wantErr: ErrUserBanned, denyResult: "unavailable", banResult: "denied"},
		{name: "revoke despite ban unavailable", denied: true, banErr: ErrRedisUnavailable, wantErr: ErrInvalidToken, denyResult: "denied", banResult: "unavailable"},
		{name: "ban command failure", banErr: commandErr, wantErr: ErrCheckUnavailable, denyResult: "clear", banResult: "error"},
		{name: "deny command failure", denyErr: commandErr, wantErr: ErrCheckUnavailable, denyResult: "error", banResult: "clear"},
		{name: "ban despite deny command failure", banned: true, denyErr: commandErr, wantErr: ErrUserBanned, denyResult: "error", banResult: "denied"},
		{name: "revoke despite ban command failure", denied: true, banErr: commandErr, wantErr: ErrInvalidToken, denyResult: "denied", banResult: "error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &denylistStub{denied: tc.denied, banned: tc.banned, err: tc.denyErr, banErr: tc.banErr}
			ctx, diagnostics := requestcontext.WithDiagnostics(t.Context())
			token := signTestToken(t, jwt.SigningMethodHS512, testSigningKey, accessClaims())
			identity, err := newTestVerifier(t, store).VerifyAccessToken(ctx, token)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error=%v, want %v", err, tc.wantErr)
			}
			if store.calls != 1 || store.banCalls != 1 || store.userID != testUserID || store.jti != testJTI {
				t.Fatalf("checks=%+v", store)
			}
			if err == nil && identity.UserID != testUserID {
				t.Fatalf("identity=%+v", identity)
			}
			fields := diagnostics.Snapshot()
			if fields.DenylistResult != tc.denyResult || fields.BanlistResult != tc.banResult {
				t.Errorf("diagnostics=%+v", fields)
			}
		})
	}
}

func TestVerifierRoleClaimDoesNotInvalidateOtherOperations(t *testing.T) {
	for _, role := range []any{"ADMIN", "MODERATOR", "USER", "OWNER", 123, []string{"ADMIN"}, nil} {
		claims := accessClaims()
		claims["role"] = role
		identity, err := newTestVerifier(t, &denylistStub{}).VerifyAccessToken(t.Context(), signTestToken(t, jwt.SigningMethodHS512, testSigningKey, claims))
		if err != nil {
			t.Fatal(err)
		}
		want, _ := role.(string)
		if want != "ADMIN" && want != "MODERATOR" && want != "USER" {
			want = ""
		}
		if identity.Role != want {
			t.Errorf("role %v: got %q, want %q", role, identity.Role, want)
		}
	}
}

func TestVerifierInvalidTokenSkipsBothLists(t *testing.T) {
	store := &denylistStub{}
	if _, err := newTestVerifier(t, store).VerifyAccessToken(context.Background(), "invalid"); !errors.Is(err, ErrInvalidToken) {
		t.Fatal(err)
	}
	if store.calls != 0 || store.banCalls != 0 {
		t.Fatalf("invalid JWT queried Redis: %+v", store)
	}
}
