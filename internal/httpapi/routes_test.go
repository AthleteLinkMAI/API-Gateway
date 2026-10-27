package httpapi_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gitlab.com/team-anonyms/athelete-link/api-gateway/internal/httpapi"
	"gitlab.com/team-anonyms/athelete-link/api-gateway/internal/requestcontext"
)

type routeVerifier struct{}

func (routeVerifier) VerifyAccessToken(context.Context, string) (requestcontext.Identity, error) {
	return requestcontext.Identity{UserID: "123e4567-e89b-42d3-a456-426614174001"}, nil
}

func TestAllServiceOperationRoutes(t *testing.T) {
	t.Parallel()

	const userID = "123e4567-e89b-42d3-a456-426614174001"
	tests := []struct {
		method   string
		path     string
		upstream string
	}{
		{http.MethodGet, "/api/v1/requests/users/" + userID, "core"},
		{http.MethodGet, "/api/v1/requests/123", "core"},
		{http.MethodPut, "/api/v1/requests/123", "core"},
		{http.MethodGet, "/api/v1/requests", "core"},
		{http.MethodPost, "/api/v1/requests", "core"},
		{http.MethodPost, "/api/v1/requests/123/rounds/1/result", "core"},
		{http.MethodPost, "/api/v1/requests/123/complete", "core"},
		{http.MethodPost, "/api/v1/requests/123/start", "core"},
		{http.MethodPost, "/api/v1/requests/123/registration/open", "core"},
		{http.MethodPost, "/api/v1/requests/123/registration/close", "core"},
		{http.MethodPost, "/api/v1/requests/123/leave", "core"},
		{http.MethodPost, "/api/v1/requests/123/kick/456", "core"},
		{http.MethodPost, "/api/v1/requests/123/join", "core"},
		{http.MethodPost, "/api/v1/requests/123/cancel", "core"},
		{http.MethodGet, "/api/v1/sports", "core"},
		{http.MethodPut, "/api/v1/user/update-user", "auth"},
		{http.MethodPut, "/api/v1/user/change-password", "auth"},
		{http.MethodPut, "/api/v1/user/change-email", "auth"},
		{http.MethodPost, "/api/v1/verification/verify-password-reset", "auth"},
		{http.MethodPost, "/api/v1/verification/verify-email", "auth"},
		{http.MethodPost, "/api/v1/verification/send-password-reset-code", "auth"},
		{http.MethodPost, "/api/v1/verification/send-email-verification-code", "auth"},
		{http.MethodPost, "/api/v1/user/register", "auth"},
		{http.MethodGet, "/api/v1/user", "auth"},
		{http.MethodGet, "/api/v1/user/me", "auth"},
		{http.MethodPost, "/api/v1/auth/refresh", "auth"},
		{http.MethodPost, "/api/v1/auth/login", "auth"},
		{http.MethodGet, "/api/v1/session/get-all/" + userID, "auth"},
		{http.MethodDelete, "/api/v1/user/delete", "auth"},
		{http.MethodDelete, "/api/v1/session/terminate/" + userID, "auth"},
		{http.MethodDelete, "/api/v1/session/terminate-all/" + userID, "auth"},
		{http.MethodDelete, "/api/v1/auth/logout", "auth"},
		{http.MethodGet, "/api/v1/results/by-request/" + userID, "game"},
		{http.MethodGet, "/api/v1/rank-tiers", "game"},
		{http.MethodGet, "/api/v1/players/" + userID, "game"},
		{http.MethodGet, "/api/v1/players/" + userID + "/other-sports", "game"},
		{http.MethodGet, "/api/v1/players/" + userID + "/last-game", "game"},
		{http.MethodGet, "/api/v1/players/" + userID + "/best-sport", "game"},
		{http.MethodGet, "/api/v1/players", "game"},
		{http.MethodGet, "/api/v1/players/", "game"},
		{http.MethodGet, "/api/v1/players/" + userID + "/sports/7", "game"},
		{http.MethodGet, "/api/v1/players/" + userID + "/matches", "game"},
		{http.MethodGet, "/api/v1/leaderboards/7", "game"},
	}
	if len(tests) != 43 {
		t.Fatalf("operation cases = %d, want 43", len(tests))
	}

	for _, tc := range tests {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			t.Parallel()
			calls := 0
			gotUpstream, gotMethod, gotURI := "", "", ""
			makeHandler := func(upstream string) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls++
					gotUpstream, gotMethod, gotURI = upstream, r.Method, r.URL.RequestURI()
					w.WriteHeader(http.StatusAccepted)
				})
			}
			handler := newOperationRoutingHandler(makeHandler("auth"), makeHandler("game"), makeHandler("core"))
			uri := tc.path + "?cursor=abc%2Fdef"
			wantURI := uri
			if tc.upstream == "auth" && (tc.method == http.MethodPut || tc.path == "/api/v1/user/me" || tc.path == "/api/v1/user/delete" || tc.path == "/api/v1/verification/verify-email" || tc.path == "/api/v1/verification/send-email-verification-code") {
				wantURI = tc.path + "/" + userID + "?cursor=abc%2Fdef"
			}
			request := httptest.NewRequestWithContext(t.Context(), tc.method, uri, nil)
			request.Header.Set("Authorization", "Bearer test-token")
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusAccepted || calls != 1 ||
				gotUpstream != tc.upstream || gotMethod != tc.method || gotURI != wantURI {
				t.Errorf("status = %d, calls = %d, upstream = %q, method = %q, URI = %q; want 202, 1, %q, %q, %q",
					recorder.Code, calls, gotUpstream, gotMethod, gotURI, tc.upstream, tc.method, wantURI)
			}
			if got := recorder.Header().Get("X-Request-Id"); got != "gateway-request-id" {
				t.Errorf("X-Request-Id = %q, want gateway-request-id", got)
			}

			wrongMethod := http.MethodHead
			wrong := serveRequest(handler, wrongMethod, tc.path)
			if wrong.Code != http.StatusMethodNotAllowed || !strings.Contains(wrong.Header().Get("Allow"), tc.method) || calls != 1 {
				t.Errorf("wrong method: status = %d, Allow = %q, calls = %d; want 405, %q, 1",
					wrong.Code, wrong.Header().Get("Allow"), calls, tc.method)
			}
		})
	}
}

func TestServiceRouteBoundaries(t *testing.T) {
	t.Parallel()

	handler := newOperationRoutingHandler(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) }),
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) }),
	)
	for _, path := range []string{
		"/api/v1/requests/123/rounds",
		"/api/v1/health",
		"/api/v1/auth/unknown",
		"/user",
		"/api/v1/user/",
		"/api/v1/user/123",
		"/api/v1/user/update-user/",
		"/api/v1/user/update-user/123",
		"/api/v1/user/change-password/123",
		"/api/v1/user/change-email/123",
		"/api/v1/user/delete/123",
		"/api/v1/verification/verify-email/123",
		"/api/v1/verification/send-email-verification-code/123",
		"/api/v1/user/update-user/a/b",
		"/api/v1/user/update-user/a%2Fb",
		"/api/v1/user/update-user/.",
		"/api/v1/user/me/",
		"/api/v1/user/me/123",
		"/api/v1/players-extra/123",
		"/api/v1/players/123/",
		"/api/v1/players//matches",
	} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			if got := serveRequest(handler, http.MethodGet, path).Code; got != http.StatusNotFound {
				t.Errorf("status = %d, want 404", got)
			}
		})
	}
}

func TestServicePreflightChecksDeclaredMethod(t *testing.T) {
	t.Parallel()

	calls := 0
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusAccepted)
	})
	handler := newOperationRoutingHandler(upstream, upstream)
	for _, tc := range []struct {
		path            string
		requestedMethod string
		wantStatus      int
		wantAllow       string
	}{
		{"/api/v1/auth/login", http.MethodPost, http.StatusNoContent, ""},
		{"/api/v1/auth/login", http.MethodGet, http.StatusMethodNotAllowed, http.MethodPost},
		{"/api/v1/players/123", http.MethodGet, http.StatusNoContent, ""},
		{"/api/v1/players/123/other-sports", http.MethodGet, http.StatusNoContent, ""},
		{"/api/v1/players/123/last-game", http.MethodGet, http.StatusNoContent, ""},
		{"/api/v1/players/123/best-sport", http.MethodGet, http.StatusNoContent, ""},
		{"/api/v1/players", http.MethodGet, http.StatusNoContent, ""},
		{"/api/v1/players/", http.MethodGet, http.StatusNoContent, ""},
		{"/api/v1/user/me", http.MethodGet, http.StatusNoContent, ""},
		{"/api/v1/user", http.MethodGet, http.StatusNoContent, ""},
		{"/api/v1/user", http.MethodPost, http.StatusMethodNotAllowed, http.MethodGet},
		{"/api/v1/user/me/123", http.MethodGet, http.StatusNotFound, ""},
		{"/api/v1/requests", http.MethodGet, http.StatusNoContent, ""},
		{"/api/v1/requests", http.MethodPost, http.StatusNoContent, ""},
		{"/api/v1/requests", http.MethodDelete, http.StatusMethodNotAllowed, "GET, POST"},
		{"/api/v1/requests/123", http.MethodGet, http.StatusNoContent, ""},
		{"/api/v1/requests/123", http.MethodPut, http.StatusNoContent, ""},
		{"/api/v1/requests/123", http.MethodPatch, http.StatusMethodNotAllowed, "GET, PUT"},
		{"/api/v1/requests/users/123", http.MethodGet, http.StatusNoContent, ""},
		{"/api/v1/requests/123/rounds", http.MethodGet, http.StatusNotFound, ""},
		{"/api/v1/requests/123/future", http.MethodPost, http.StatusNotFound, ""},
		{"/api/v1/health", http.MethodGet, http.StatusNotFound, ""},
	} {
		request := httptest.NewRequestWithContext(t.Context(), http.MethodOptions, tc.path, nil)
		request.Header.Set("Origin", "https://app.example")
		request.Header.Set("Access-Control-Request-Method", tc.requestedMethod)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != tc.wantStatus || recorder.Header().Get("Allow") != tc.wantAllow {
			t.Errorf("OPTIONS %s (%s): status = %d, Allow = %q; want %d, %q",
				tc.path, tc.requestedMethod, recorder.Code, recorder.Header().Get("Allow"), tc.wantStatus, tc.wantAllow)
		}
	}
	if calls != 0 {
		t.Errorf("upstream calls = %d, want 0", calls)
	}
}

func newOperationRoutingHandler(authHandler, gameHandler http.Handler, coreHandlers ...http.Handler) http.Handler {
	coreHandler := http.NotFoundHandler()
	if len(coreHandlers) > 0 {
		coreHandler = coreHandlers[0]
	}
	return httpapi.NewHandler(httpapi.HandlerOptions{
		Readiness:       &httpapi.Readiness{},
		CheckDependency: func(context.Context) error { return nil },
		CoreProxy:       coreHandler,
		AuthHandler:     authHandler,
		GameHandler:     gameHandler,
		CoreTimeout:     time.Second,
		AuthTimeout:     time.Second,
		GameTimeout:     time.Second,
		WriteTimeout:    2 * time.Second,
		Verifier:        routeVerifier{},
		NewRequestID:    func() string { return "gateway-request-id" },
		CORSOrigins:     []string{"https://app.example"},
	})
}
