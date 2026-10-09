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

func TestAuthAndGamePreflightRunsBeforeAuthentication(t *testing.T) {
	const allowedOrigin = "https://app.example"
	const userID = "123e4567-e89b-42d3-a456-426614174001"

	for _, tc := range []struct {
		name, path, origin, requestedMethod string
		wantStatus                          int
		wantAllow, wantOrigin, wantMethod   string
	}{
		{"public Auth", "/api/v1/auth/login", allowedOrigin, http.MethodPost,
			http.StatusNoContent, "", allowedOrigin, http.MethodPost},
		{"localhost registration", "/api/v1/user/register", "http://localhost:8079", http.MethodPost,
			http.StatusNoContent, "", "http://localhost:8079", http.MethodPost},
		{"protected Auth", "/api/v1/session/get-all/" + userID, allowedOrigin, http.MethodGet,
			http.StatusNoContent, "", allowedOrigin, http.MethodGet},
		{"Game", "/api/v1/players/" + userID, allowedOrigin, http.MethodGet,
			http.StatusNoContent, "", allowedOrigin, http.MethodGet},
		{"localhost unsupported method", "/api/v1/user/me", "http://localhost:5173", http.MethodPost,
			http.StatusMethodNotAllowed, http.MethodGet, "http://localhost:5173", ""},
		{"unsupported method", "/api/v1/auth/login", allowedOrigin, http.MethodGet,
			http.StatusMethodNotAllowed, http.MethodPost, allowedOrigin, ""},
		{"foreign origin", "/api/v1/auth/login", "https://foreign.example", http.MethodPost,
			http.StatusForbidden, "", "", ""},
		{"unknown path", "/api/v1/auth/unknown", allowedOrigin, http.MethodPost,
			http.StatusNotFound, "", "", ""},
		{"ordinary OPTIONS", "/api/v1/auth/login", allowedOrigin, "",
			http.StatusMethodNotAllowed, http.MethodPost, allowedOrigin, ""},
		{"no origin", "/api/v1/user/register", "", http.MethodPost,
			http.StatusMethodNotAllowed, http.MethodPost, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verifier := &accessRouteVerifier{identity: requestcontext.Identity{UserID: userID}}
			upstreamCalls := 0
			upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				upstreamCalls++
				w.WriteHeader(http.StatusAccepted)
			})
			handler := newAccessRouteHandler(verifier, upstream, upstream)
			request := httptest.NewRequestWithContext(t.Context(), http.MethodOptions, tc.path, nil)
			request.Header.Set("Origin", tc.origin)
			if tc.requestedMethod != "" {
				request.Header.Set("Access-Control-Request-Method", tc.requestedMethod)
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)

			if recorder.Code != tc.wantStatus || recorder.Header().Get("Allow") != tc.wantAllow {
				t.Errorf("status = %d, Allow = %q; want %d, %q",
					recorder.Code, recorder.Header().Get("Allow"), tc.wantStatus, tc.wantAllow)
			}
			if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != tc.wantOrigin {
				t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, tc.wantOrigin)
			}
			if got := recorder.Header().Get("Access-Control-Allow-Methods"); got != tc.wantMethod {
				t.Errorf("Access-Control-Allow-Methods = %q, want %q", got, tc.wantMethod)
			}
			if tc.wantStatus == http.StatusNoContent {
				if got := recorder.Header().Get("Access-Control-Allow-Headers"); !strings.Contains(got, "Authorization") {
					t.Errorf("Access-Control-Allow-Headers = %q, want Authorization", got)
				}
			}
			wantCredentials := ""
			if tc.wantOrigin != "" {
				wantCredentials = "true"
			}
			if got := recorder.Header().Get("Access-Control-Allow-Credentials"); got != wantCredentials {
				t.Errorf("Access-Control-Allow-Credentials = %q, want %q", got, wantCredentials)
			}
			if got := recorder.Header().Get("X-Request-Id"); got != httpTestRequestID {
				t.Errorf("X-Request-Id = %q, want %q", got, httpTestRequestID)
			}
			if tc.wantStatus != http.StatusNotFound {
				vary := strings.Join(recorder.Header().Values("Vary"), ",")
				if !strings.Contains(vary, "Origin") {
					t.Errorf("Vary = %q, want Origin", vary)
				}
				if tc.origin != "" && tc.requestedMethod != "" && (!strings.Contains(vary, "Access-Control-Request-Method") ||
					!strings.Contains(vary, "Access-Control-Request-Headers")) {
					t.Errorf("Vary = %q, want preflight request headers", vary)
				}
			}
			if verifier.calls != 0 || upstreamCalls != 0 {
				t.Errorf("verifier calls = %d, upstream calls = %d; want 0, 0", verifier.calls, upstreamCalls)
			}
		})
	}
}

func TestAuthAndGameCORSOnOrdinaryResponses(t *testing.T) {
	const allowedOrigin = "https://app.example"
	const userID = "123e4567-e89b-42d3-a456-426614174001"

	for _, tc := range []struct {
		name, method, path, origin string
		bearer                     bool
		wantStatus                 int
		wantOrigin                 string
		wantCalls                  int
	}{
		{"Auth login", http.MethodPost, "/api/v1/auth/login", allowedOrigin, false,
			http.StatusAccepted, allowedOrigin, 1},
		{"localhost registration", http.MethodPost, "/api/v1/user/register", "http://localhost:8079", false,
			http.StatusAccepted, "http://localhost:8079", 1},
		{"Auth refresh", http.MethodPost, "/api/v1/auth/refresh", allowedOrigin, false,
			http.StatusAccepted, allowedOrigin, 1},
		{"protected Auth without JWT", http.MethodGet, "/api/v1/session/get-all/" + userID, allowedOrigin, false,
			http.StatusUnauthorized, allowedOrigin, 0},
		{"localhost me without JWT", http.MethodGet, "/api/v1/user/me", "http://localhost:5173", false,
			http.StatusUnauthorized, "http://localhost:5173", 0},
		{"Game with JWT", http.MethodGet, "/api/v1/rank-tiers", allowedOrigin, true,
			http.StatusAccepted, allowedOrigin, 1},
		{"wrong method", http.MethodGet, "/api/v1/auth/login", allowedOrigin, false,
			http.StatusMethodNotAllowed, allowedOrigin, 0},
		{"foreign origin", http.MethodPost, "/api/v1/auth/login", "https://foreign.example", false,
			http.StatusAccepted, "", 1},
		{"no origin", http.MethodPost, "/api/v1/auth/login", "", false,
			http.StatusAccepted, "", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verifier := &accessRouteVerifier{identity: requestcontext.Identity{UserID: userID}}
			upstreamCalls := 0
			upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamCalls++
				if strings.HasPrefix(r.URL.Path, "/api/v1/auth/") {
					if got := r.Header.Get("Cookie"); got != "refreshToken=old" {
						t.Errorf("Auth Cookie = %q, want refreshToken=old", got)
					}
					w.Header().Add("Set-Cookie", "refreshToken=new; HttpOnly")
				}
				w.WriteHeader(http.StatusAccepted)
			})
			handler := newAccessRouteHandler(verifier, upstream, upstream)
			request := httptest.NewRequestWithContext(t.Context(), tc.method, tc.path, nil)
			if tc.origin != "" {
				request.Header.Set("Origin", tc.origin)
			}
			if tc.bearer {
				request.Header.Set("Authorization", "Bearer verified-token")
			}
			request.Header.Set("Cookie", "refreshToken=old")
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)

			if recorder.Code != tc.wantStatus || upstreamCalls != tc.wantCalls {
				t.Errorf("status = %d, upstream calls = %d; want %d, %d",
					recorder.Code, upstreamCalls, tc.wantStatus, tc.wantCalls)
			}
			if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != tc.wantOrigin {
				t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, tc.wantOrigin)
			}
			wantCredentials := ""
			if tc.wantOrigin != "" {
				wantCredentials = "true"
			}
			if got := recorder.Header().Get("Access-Control-Allow-Credentials"); got != wantCredentials {
				t.Errorf("Access-Control-Allow-Credentials = %q, want %q", got, wantCredentials)
			}
			if got := strings.Join(recorder.Header().Values("Vary"), ","); !strings.Contains(got, "Origin") {
				t.Errorf("Vary = %q, want Origin", got)
			}
			if tc.wantCalls == 1 && strings.HasPrefix(tc.path, "/api/v1/auth/") {
				if got := recorder.Header().Values("Set-Cookie"); len(got) != 1 || got[0] != "refreshToken=new; HttpOnly" {
					t.Errorf("Set-Cookie = %q, want upstream cookie", got)
				}
			}
			if tc.name == "wrong method" && recorder.Header().Get("Allow") != http.MethodPost {
				t.Errorf("Allow = %q, want POST", recorder.Header().Get("Allow"))
			}
		})
	}
}

func TestLocalhostCORSWithAndWithoutConfiguredOrigins(t *testing.T) {
	t.Parallel()
	for _, config := range []struct {
		name    string
		origins []string
	}{
		{"no configured origins", nil},
		{"configured origins", []string{"https://app.example"}},
	} {
		for _, tc := range []struct {
			origin  string
			allowed bool
		}{
			{"http://localhost", true},
			{"https://localhost", true},
			{"http://localhost:3000", true},
			{"http://localhost:8079", true},
			{"https://localhost:5173", true},
			{"http://localhost:1", true},
			{"https://localhost:65535", true},
			{"http://LOCALHOST:8080", true},
			{"https://app.example", len(config.origins) > 0},
			{"http://localhost:0", false},
			{"http://localhost:65536", false},
			{"http://localhost:999999999999999999999", false},
			{"http://localhost:abc", false},
			{"http://localhost:", false},
			{"http://localhost/", false},
			{"http://localhost/path", false},
			{"http://localhost?x=1", false},
			{"http://localhost?", false},
			{"http://localhost#fragment", false},
			{"http://localhost#", false},
			{"http://user@localhost", false},
			{"http:localhost", false},
			{"//localhost", false},
			{"ftp://localhost", false},
			{"http://localhost.example", false},
			{"http://sub.localhost", false},
			{"http://localhost.evil:3000", false},
			{"http://127.0.0.1:3000", false},
			{"http://[::1]:3000", false},
			{"http://[localhost]:3000", false},
			{"null", false},
		} {
			for _, path := range []string{"/api/v1/user/me", "/api/v1/rank-tiers", "/api/v1/sports"} {
				t.Run(config.name+"/"+tc.origin+path, func(t *testing.T) {
					verifier := &accessRouteVerifier{identity: requestcontext.Identity{UserID: httpTestUserID}}
					calls := 0
					upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						calls++
						w.WriteHeader(http.StatusAccepted)
					})
					handler := httpapi.NewHandler(httpapi.HandlerOptions{
						Readiness:       &httpapi.Readiness{},
						CheckDependency: func(context.Context) error { return nil },
						CoreProxy:       upstream, AuthHandler: upstream, GameHandler: upstream,
						CoreTimeout: time.Second, AuthTimeout: time.Second, GameTimeout: time.Second,
						WriteTimeout: 2 * time.Second, Verifier: verifier,
						NewRequestID: func() string { return httpTestRequestID },
						CORSOrigins:  config.origins,
					})
					wantOrigin, wantCredentials, wantPreflightStatus := "", "", http.StatusForbidden
					if tc.allowed {
						wantOrigin, wantCredentials, wantPreflightStatus = tc.origin, "true", http.StatusNoContent
					}
					preflight := httptest.NewRequestWithContext(t.Context(), http.MethodOptions, path, nil)
					preflight.Header.Set("Origin", tc.origin)
					preflight.Header.Set("Access-Control-Request-Method", http.MethodGet)
					preflight.Header.Set("Access-Control-Request-Headers", "Authorization, Content-Type")
					response := httptest.NewRecorder()
					handler.ServeHTTP(response, preflight)
					if response.Code != wantPreflightStatus || response.Header().Get("Access-Control-Allow-Origin") != wantOrigin || calls != 0 || verifier.calls != 0 {
						t.Fatalf("preflight status=%d, origin=%q, calls=%d, verifier=%d", response.Code, response.Header().Get("Access-Control-Allow-Origin"), calls, verifier.calls)
					}
					if tc.allowed && (response.Header().Get("Access-Control-Allow-Methods") != http.MethodGet || response.Header().Get("Access-Control-Allow-Headers") != "Authorization, Content-Type") {
						t.Error("preflight did not preserve allowed method and headers")
					}
					if response.Header().Get("Access-Control-Allow-Credentials") != wantCredentials || !strings.Contains(strings.Join(response.Header().Values("Vary"), ","), "Origin") {
						t.Error("preflight credentials/Vary policy mismatch")
					}
					request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
					request.Header.Set("Origin", tc.origin)
					request.Header.Set("Authorization", "Bearer verified-token")
					response = httptest.NewRecorder()
					handler.ServeHTTP(response, request)
					if response.Code != http.StatusAccepted || response.Header().Get("Access-Control-Allow-Origin") != wantOrigin || calls != 1 || verifier.calls != 1 {
						t.Errorf("ordinary response status=%d, origin=%q, calls=%d, verifier=%d", response.Code, response.Header().Get("Access-Control-Allow-Origin"), calls, verifier.calls)
					}
					if response.Header().Get("Access-Control-Allow-Credentials") != wantCredentials || !strings.Contains(strings.Join(response.Header().Values("Vary"), ","), "Origin") {
						t.Error("ordinary response credentials/Vary policy mismatch")
					}
				})
			}
		}
	}
}
