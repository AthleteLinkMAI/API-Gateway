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
	return requestcontext.Identity{UserID: "123e4567-e89b-42d3-a456-426614174001", Role: "USER"}, nil
}

func TestAllServiceOperationRoutes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		method   string
		path     string
		upstream string
	}{
		{http.MethodPut, "/api/v1/user/role", "auth"},
		{http.MethodPut, "/api/v1/user/password", "auth"},
		{http.MethodPut, "/api/v1/user/email", "auth"},
		{http.MethodPost, "/api/v1/verification/send-password-reset-code", "auth"},
		{http.MethodPost, "/api/v1/verification/send-email-verification-code", "auth"},
		{http.MethodPost, "/api/v1/verification/password-reset", "auth"},
		{http.MethodPost, "/api/v1/verification/email", "auth"},
		{http.MethodPost, "/api/v1/user", "auth"},
		{http.MethodDelete, "/api/v1/user", "auth"},
		{http.MethodPost, "/api/v1/ban", "auth"},
		{http.MethodDelete, "/api/v1/ban", "auth"},
		{http.MethodPost, "/api/v1/auth/refresh", "auth"},
		{http.MethodPost, "/api/v1/auth/login", "auth"},
		{http.MethodGet, "/api/v1/session", "auth"},
		{http.MethodDelete, "/api/v1/session", "auth"},
		{http.MethodGet, "/api/v1/ban/123e4567-e89b-42d3-a456-426614174001", "auth"},
		{http.MethodDelete, "/api/v1/session/all", "auth"},
		{http.MethodDelete, "/api/v1/auth/logout", "auth"},
		{http.MethodGet, "/api/v1/user", "profile"},
		{http.MethodPut, "/api/v1/user", "profile"},
		{http.MethodPost, "/api/v1/friend/request", "profile"},
		{http.MethodDelete, "/api/v1/friend/request", "profile"},
		{http.MethodPost, "/api/v1/friend/request/decline", "profile"},
		{http.MethodPost, "/api/v1/friend/request/accept", "profile"},
		{http.MethodGet, "/api/v1/user/me", "profile"},
		{http.MethodGet, "/api/v1/friend/123e4567-e89b-42d3-a456-426614174001", "profile"},
		{http.MethodGet, "/api/v1/friend/request/outgoing/123e4567-e89b-42d3-a456-426614174001", "profile"},
		{http.MethodGet, "/api/v1/friend/request/incoming/123e4567-e89b-42d3-a456-426614174001", "profile"},
		{http.MethodDelete, "/api/v1/friend", "profile"},
		{http.MethodGet, "/api/v1/requests/123e4567-e89b-42d3-a456-426614174001", "core"},
		{http.MethodPut, "/api/v1/requests/123e4567-e89b-42d3-a456-426614174001", "core"},
		{http.MethodGet, "/api/v1/requests", "core"},
		{http.MethodPost, "/api/v1/requests", "core"},
		{http.MethodPost, "/api/v1/requests/123e4567-e89b-42d3-a456-426614174001/join-requests/123e4567-e89b-42d3-a456-426614174001/decision", "core"},
		{http.MethodPost, "/api/v1/requests/123e4567-e89b-42d3-a456-426614174001/start", "core"},
		{http.MethodPost, "/api/v1/requests/123e4567-e89b-42d3-a456-426614174001/registration/open", "core"},
		{http.MethodPost, "/api/v1/requests/123e4567-e89b-42d3-a456-426614174001/registration/close", "core"},
		{http.MethodPost, "/api/v1/requests/123e4567-e89b-42d3-a456-426614174001/leave", "core"},
		{http.MethodPost, "/api/v1/requests/123e4567-e89b-42d3-a456-426614174001/kick/123e4567-e89b-42d3-a456-426614174001", "core"},
		{http.MethodPost, "/api/v1/requests/123e4567-e89b-42d3-a456-426614174001/join", "core"},
		{http.MethodPost, "/api/v1/requests/123e4567-e89b-42d3-a456-426614174001/cancel", "core"},
		{http.MethodGet, "/api/v1/sports", "core"},
		{http.MethodGet, "/api/v1/requests/123e4567-e89b-42d3-a456-426614174001/join-requests", "core"},
		{http.MethodGet, "/api/v1/requests/users/123e4567-e89b-42d3-a456-426614174001", "core"},
		{http.MethodPost, "/api/v1/voting", "game"},
		{http.MethodPost, "/api/v1/results", "game"},
		{http.MethodGet, "/api/v1/voting/123e4567-e89b-42d3-a456-426614174001", "game"},
		{http.MethodGet, "/api/v1/results/by-request/123e4567-e89b-42d3-a456-426614174001", "game"},
		{http.MethodGet, "/api/v1/rank-tiers", "game"},
		{http.MethodGet, "/api/v1/players/123e4567-e89b-42d3-a456-426614174001", "game"},
		{http.MethodGet, "/api/v1/players/123e4567-e89b-42d3-a456-426614174001/sports/123e4567-e89b-42d3-a456-426614174001", "game"},
		{http.MethodGet, "/api/v1/players/123e4567-e89b-42d3-a456-426614174001/other-sports", "game"},
		{http.MethodGet, "/api/v1/players/123e4567-e89b-42d3-a456-426614174001/matches/123e4567-e89b-42d3-a456-426614174001/123e4567-e89b-42d3-a456-426614174001", "game"},
		{http.MethodGet, "/api/v1/players/123e4567-e89b-42d3-a456-426614174001/last-game", "game"},
		{http.MethodGet, "/api/v1/players/123e4567-e89b-42d3-a456-426614174001/best-sport", "game"},
		{http.MethodGet, "/api/v1/leaderboards/123e4567-e89b-42d3-a456-426614174001/123e4567-e89b-42d3-a456-426614174001/123e4567-e89b-42d3-a456-426614174001", "game"},
		{http.MethodGet, "/api/v1/report", "chat"},
		{http.MethodPost, "/api/v1/report", "chat"},
		{http.MethodPost, "/api/v1/message/private", "chat"},
		{http.MethodPost, "/api/v1/message/chat", "chat"},
		{http.MethodPost, "/api/v1/message/activity-request", "chat"},
		{http.MethodGet, "/api/v1/report/123e4567-e89b-42d3-a456-426614174001", "chat"},
		{http.MethodGet, "/api/v1/report/all", "chat"},
		{http.MethodGet, "/api/v1/message/private/123e4567-e89b-42d3-a456-426614174001", "chat"},
		{http.MethodGet, "/api/v1/message/chat/123e4567-e89b-42d3-a456-426614174001", "chat"},
		{http.MethodGet, "/api/v1/message/activity-request/123e4567-e89b-42d3-a456-426614174001", "chat"},
		{http.MethodDelete, "/api/v1/report/123e4567-e89b-42d3-a456-426614174001", "chat"},
		{http.MethodGet, "/api/v1/players", "game"},
		{http.MethodGet, "/api/v1/players/", "game"},
	}
	if len(tests) != 69 {
		t.Fatalf("operation cases = %d, want 69", len(tests))
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
			handler := newOperationRoutingHandler(makeHandler("auth"), makeHandler("game"), makeHandler("core"), makeHandler("profile"), makeHandler("chat"))
			uri := tc.path + "?marker=abc%2Fdef"
			wantURI := uri
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
		"/api/v1/players/123/matches",
		"/api/v1/leaderboards/7",
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
		{"/api/v1/players/123/matches/0/20", http.MethodGet, http.StatusNoContent, ""},
		{"/api/v1/leaderboards/7/0/20", http.MethodGet, http.StatusNoContent, ""},
		{"/api/v1/players/123/matches", http.MethodGet, http.StatusNotFound, ""},
		{"/api/v1/leaderboards/7", http.MethodGet, http.StatusNotFound, ""},
		{"/api/v1/players", http.MethodGet, http.StatusNoContent, ""},
		{"/api/v1/players/", http.MethodGet, http.StatusNoContent, ""},
		{"/api/v1/user/me", http.MethodGet, http.StatusNoContent, ""},
		{"/api/v1/user", http.MethodGet, http.StatusNoContent, ""},
		{"/api/v1/user", http.MethodPost, http.StatusNoContent, ""},
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
	profileHandler, chatHandler := authHandler, gameHandler
	if len(coreHandlers) > 1 {
		profileHandler = coreHandlers[1]
	}
	if len(coreHandlers) > 2 {
		chatHandler = coreHandlers[2]
	}
	return httpapi.NewHandler(httpapi.HandlerOptions{
		Readiness:       &httpapi.Readiness{},
		CheckDependency: func(context.Context) error { return nil },
		CoreProxy:       coreHandler,
		AuthHandler:     authHandler,
		GameHandler:     gameHandler,
		ProfileHandler:  profileHandler, ChatHandler: chatHandler,
		CoreTimeout:    time.Second,
		AuthTimeout:    time.Second,
		GameTimeout:    time.Second,
		ProfileTimeout: time.Second, ChatTimeout: time.Second,
		WriteTimeout: 2 * time.Second,
		Verifier:     routeVerifier{},
		NewRequestID: func() string { return "gateway-request-id" },
		CORSOrigins:  []string{"https://app.example"},
	})
}
