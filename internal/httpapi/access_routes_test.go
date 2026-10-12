package httpapi_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gitlab.com/team-anonyms/athelete-link/api-gateway/internal/auth"
	"gitlab.com/team-anonyms/athelete-link/api-gateway/internal/httpapi"
	"gitlab.com/team-anonyms/athelete-link/api-gateway/internal/requestcontext"
)

type accessRouteVerifier struct {
	identity requestcontext.Identity
	err      error
	calls    int
	token    string
}

func (v *accessRouteVerifier) VerifyAccessToken(_ context.Context, token string) (requestcontext.Identity, error) {
	v.calls++
	v.token = token
	return v.identity, v.err
}

func newAccessRouteHandler(verifier httpapi.AccessVerifier, authHandler, gameHandler http.Handler) http.Handler {
	return httpapi.NewHandler(httpapi.HandlerOptions{
		Readiness:       &httpapi.Readiness{},
		CheckDependency: func(context.Context) error { return nil },
		CoreProxy:       http.NotFoundHandler(),
		AuthHandler:     authHandler,
		GameHandler:     gameHandler,
		CoreTimeout:     time.Second,
		AuthTimeout:     time.Second,
		GameTimeout:     time.Second,
		WriteTimeout:    2 * time.Second,
		Verifier:        verifier,
		NewRequestID:    func() string { return httpTestRequestID },
		CORSOrigins:     []string{"https://app.example"},
	})
}

func TestProtectedAuthPreflightBypassesAccessVerifier(t *testing.T) {
	verifier := &accessRouteVerifier{err: errors.New("must not be called")}
	calls := 0
	authHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusAccepted)
	})
	handler := newAccessRouteHandler(verifier, authHandler, http.NotFoundHandler())
	request := httptest.NewRequestWithContext(t.Context(), http.MethodOptions, "/api/v1/session/get-all/"+httpTestUserID, nil)
	request.Header.Set("Origin", "https://app.example")
	request.Header.Set("Access-Control-Request-Method", http.MethodGet)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || verifier.calls != 0 || calls != 0 {
		t.Errorf("status = %d, verifier calls = %d, upstream calls = %d; want 204, 0, 0",
			response.Code, verifier.calls, calls)
	}
}

func TestPublicAuthOperationsBypassAccessVerifier(t *testing.T) {
	for _, path := range []string{
		"/api/v1/verification/verify-password-reset",
		"/api/v1/verification/send-password-reset-code",
		"/api/v1/user/register",
		"/api/v1/auth/refresh",
		"/api/v1/auth/login",
	} {
		t.Run(path, func(t *testing.T) {
			verifier := &accessRouteVerifier{err: errors.New("must not be called")}
			calls := 0
			authHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if _, ok := requestcontext.IdentityFrom(r.Context()); ok {
					t.Error("public Auth request has a verified identity")
				}
				if _, ok := requestcontext.VerifiedAccessTokenFrom(r.Context()); ok {
					t.Error("public Auth request has a verified access token")
				}
				w.WriteHeader(http.StatusAccepted)
			})
			handler := newAccessRouteHandler(verifier, authHandler, http.NotFoundHandler())
			response := serveRequest(handler, http.MethodPost, path)
			if response.Code != http.StatusAccepted || calls != 1 || verifier.calls != 0 {
				t.Errorf("status = %d, upstream calls = %d, verifier calls = %d; want 202, 1, 0",
					response.Code, calls, verifier.calls)
			}
		})
	}
}

func TestProtectedAuthAndGameOperationsRequireBearer(t *testing.T) {
	const otherUser = "123e4567-e89b-42d3-a456-426614174099"
	for _, tc := range []struct{ method, path string }{
		{http.MethodPut, "/api/v1/user/update-user"},
		{http.MethodPut, "/api/v1/user/change-password"},
		{http.MethodPut, "/api/v1/user/change-email"},
		{http.MethodPost, "/api/v1/verification/verify-email"},
		{http.MethodPost, "/api/v1/verification/send-email-verification-code"},
		{http.MethodGet, "/api/v1/session/get-all/" + httpTestUserID},
		{http.MethodDelete, "/api/v1/user/delete"},
		{http.MethodDelete, "/api/v1/session/terminate/" + httpTestUserID},
		{http.MethodDelete, "/api/v1/session/terminate-all/" + httpTestUserID},
		{http.MethodDelete, "/api/v1/auth/logout"},
		{http.MethodGet, "/api/v1/user/me"},
		{http.MethodGet, "/api/v1/user?userIds=" + otherUser},
		{http.MethodGet, "/api/v1/results/by-request/" + otherUser},
		{http.MethodGet, "/api/v1/rank-tiers"},
		{http.MethodGet, "/api/v1/players/" + otherUser},
		{http.MethodGet, "/api/v1/players"},
		{http.MethodGet, "/api/v1/players/"},
		{http.MethodGet, "/api/v1/players/" + otherUser + "/sports/7"},
		{http.MethodGet, "/api/v1/players/" + otherUser + "/matches"},
		{http.MethodGet, "/api/v1/leaderboards/7"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			verifier := &accessRouteVerifier{identity: requestcontext.Identity{UserID: httpTestUserID}}
			calls := 0
			upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls++
				w.WriteHeader(http.StatusAccepted)
			})
			handler := newAccessRouteHandler(verifier, upstream, upstream)
			response := serveRequest(handler, tc.method, tc.path)
			if response.Code != http.StatusUnauthorized || calls != 0 || verifier.calls != 0 {
				t.Errorf("status = %d, upstream calls = %d, verifier calls = %d; want 401, 0, 0",
					response.Code, calls, verifier.calls)
			}
		})
	}
}

func TestProtectedRoutesUseVerifiedIdentityAndAuthUserID(t *testing.T) {
	const otherUser = "123e4567-e89b-42d3-a456-426614174099"
	for _, tc := range []struct {
		name       string
		method     string
		path       string
		verifyErr  error
		wantStatus int
		wantCalls  int
	}{
		{"Auth own user", http.MethodGet, "/api/v1/session/get-all/" + strings.ToUpper(httpTestUserID), nil, http.StatusAccepted, 1},
		{"Auth other user", http.MethodGet, "/api/v1/session/get-all/" + otherUser, nil, http.StatusForbidden, 0},
		{"Auth logout", http.MethodDelete, "/api/v1/auth/logout", nil, http.StatusAccepted, 1},
		{"Auth current user", http.MethodGet, "/api/v1/user/me", nil, http.StatusAccepted, 1},
		{"Auth user lookup", http.MethodGet, "/api/v1/user?userIds=" + otherUser, nil, http.StatusAccepted, 1},
		{"Game other player", http.MethodGet, "/api/v1/players/" + otherUser, nil, http.StatusAccepted, 1},
		{"invalid me token", http.MethodGet, "/api/v1/user/me", auth.ErrInvalidToken, http.StatusUnauthorized, 0},
		{"invalid user lookup token", http.MethodGet, "/api/v1/user?userIds=" + otherUser, auth.ErrInvalidToken, http.StatusUnauthorized, 0},
		{"invalid access token", http.MethodDelete, "/api/v1/auth/logout", auth.ErrInvalidToken, http.StatusUnauthorized, 0},
		{"denylist check unavailable", http.MethodGet, "/api/v1/rank-tiers", auth.ErrCheckUnavailable, http.StatusServiceUnavailable, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verifier := &accessRouteVerifier{
				identity: requestcontext.Identity{UserID: httpTestUserID}, err: tc.verifyErr,
			}
			calls := 0
			upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				identity, identityOK := requestcontext.IdentityFrom(r.Context())
				token, tokenOK := requestcontext.VerifiedAccessTokenFrom(r.Context())
				if !identityOK || identity.UserID != httpTestUserID || !tokenOK || token != "verified-token" {
					t.Errorf("verified context = (%+v, %v, %q, %v)", identity, identityOK, token, tokenOK)
				}
				w.WriteHeader(http.StatusAccepted)
			})
			handler := newAccessRouteHandler(verifier, upstream, upstream)
			request := httptest.NewRequestWithContext(t.Context(), tc.method, tc.path, nil)
			request.Header.Set("Authorization", "Bearer verified-token")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != tc.wantStatus || calls != tc.wantCalls || verifier.calls != 1 || verifier.token != "verified-token" {
				t.Errorf("status = %d, upstream calls = %d, verifier calls = %d, token = %q; want %d, %d, 1, verified-token",
					response.Code, calls, verifier.calls, verifier.token, tc.wantStatus, tc.wantCalls)
			}
			if response.Header().Get("X-Request-Id") != httpTestRequestID {
				t.Error("Gateway response lost X-Request-Id")
			}
		})
	}
}
