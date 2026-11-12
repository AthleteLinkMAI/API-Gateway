package httpapi_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"gitlab.com/team-anonyms/athelete-link/api-gateway/internal/auth"
	"gitlab.com/team-anonyms/athelete-link/api-gateway/internal/httpapi"
	"gitlab.com/team-anonyms/athelete-link/api-gateway/internal/requestcontext"
)

const (
	httpTestUserID    = "123e4567-e89b-42d3-a456-426614174001"
	httpTestTokenID   = "123e4567-e89b-42d3-a456-426614174002"
	httpTestRequestID = "123e4567-e89b-42d3-a456-426614174003"
	httpTestSecret    = "test-only-signing-key"
)

type httpDenylistStub struct {
	denied bool
	err    error
	calls  int
}

func (stub *httpDenylistStub) IsDenied(_ context.Context, jti string) (bool, error) {
	stub.calls++
	if jti != httpTestTokenID {
		return false, errors.New("unexpected token ID")
	}
	return stub.denied, stub.err
}

func TestCoreAuthenticationAndRequestID(t *testing.T) {
	now := time.Date(2026, time.September, 29, 12, 0, 0, 0, time.UTC)
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub":  httpTestUserID,
		"jti":  httpTestTokenID,
		"type": "ACCESS",
		"iat":  now.Add(-time.Minute).Unix(),
		"exp":  now.Add(time.Minute).Unix(),
	}).SignedString([]byte(httpTestSecret))
	if err != nil {
		t.Fatalf("sign access token: %v", err)
	}

	tests := []struct {
		name                   string
		authorization          string
		duplicateAuthorization bool
		denied                 bool
		lookupErr              error
		wantStatus             int
		wantDenylistCalls      int
		wantCoreCalls          int
	}{
		{name: "missing bearer", wantStatus: http.StatusUnauthorized},
		{name: "malformed token", authorization: "Bearer not-a-jwt", wantStatus: http.StatusUnauthorized},
		{name: "multiple bearer values", authorization: "Bearer " + token, duplicateAuthorization: true, wantStatus: http.StatusUnauthorized},
		{name: "revoked token", authorization: "Bearer " + token, denied: true, wantStatus: http.StatusUnauthorized, wantDenylistCalls: 1},
		{name: "unclassified Redis error", authorization: "Bearer " + token, lookupErr: errors.New("Redis command failed"), wantStatus: http.StatusServiceUnavailable, wantDenylistCalls: 1},
		{name: "Redis unavailable", authorization: "Bearer " + token, lookupErr: auth.ErrRedisUnavailable, wantStatus: http.StatusNoContent, wantDenylistCalls: 1, wantCoreCalls: 1},
		{name: "valid token", authorization: "Bearer " + token, wantStatus: http.StatusNoContent, wantDenylistCalls: 1, wantCoreCalls: 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			denylist := &httpDenylistStub{denied: tc.denied, err: tc.lookupErr}
			verifier, err := auth.NewVerifier(httpTestSecret, denylist, func() time.Time { return now })
			if err != nil {
				t.Fatalf("create verifier: %v", err)
			}

			coreCalls := 0
			core := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				coreCalls++
				identity, ok := requestcontext.IdentityFrom(r.Context())
				if !ok || identity.UserID != httpTestUserID {
					t.Errorf("Core identity = (%+v, %v), want verified user %q", identity, ok, httpTestUserID)
				}
				id, ok := requestcontext.RequestIDFrom(r.Context())
				if !ok || id != httpTestRequestID {
					t.Errorf("Core request ID = (%q, %v), want %q", id, ok, httpTestRequestID)
				}
				w.WriteHeader(http.StatusNoContent)
			})
			handler := httpapi.NewHandler(httpapi.HandlerOptions{
				Readiness:       &httpapi.Readiness{},
				CheckDependency: func(context.Context) error { return nil },
				CoreProxy:       core,
				CoreTimeout:     time.Second,
				WriteTimeout:    2 * time.Second,
				Verifier:        verifier,
				NewRequestID:    func() string { return httpTestRequestID },
			})
			request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/sports", nil)
			request.Header.Set("X-Request-Id", "client-request-id")
			if tc.authorization != "" {
				request.Header.Set("Authorization", tc.authorization)
			}
			if tc.duplicateAuthorization {
				request.Header.Add("Authorization", tc.authorization)
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)

			if recorder.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", recorder.Code, tc.wantStatus)
			}
			if got := recorder.Header().Get("X-Request-Id"); got != httpTestRequestID {
				t.Errorf("X-Request-Id = %q, want %q", got, httpTestRequestID)
			}
			if denylist.calls != tc.wantDenylistCalls {
				t.Errorf("denylist calls = %d, want %d", denylist.calls, tc.wantDenylistCalls)
			}
			if coreCalls != tc.wantCoreCalls {
				t.Errorf("Core calls = %d, want %d", coreCalls, tc.wantCoreCalls)
			}
		})
	}
}

func (stub *httpDenylistStub) IsBanned(context.Context, string) (bool, error) { return false, nil }
