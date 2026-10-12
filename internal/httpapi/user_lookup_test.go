package httpapi_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"gitlab.com/team-anonyms/athelete-link/api-gateway/internal/proxy"
	"gitlab.com/team-anonyms/athelete-link/api-gateway/internal/requestcontext"
)

func TestUserLookupPreservesAuthRequestAndResponse(t *testing.T) {
	t.Parallel()

	const firstUser = "123e4567-e89b-42d3-a456-426614174098"
	const secondUser = "123e4567-e89b-42d3-a456-426614174099"
	const publicUsers = "[{\"id\":\"" + secondUser + "\",\"username\":\"second\"}, {\"id\":\"" + firstUser + "\",\"username\":\"first\"}]\n"
	const authError = "{\"error\":\"Auth rejected the query\"}\n"
	for _, tc := range []struct {
		name   string
		query  string
		status int
		body   string
	}{
		{"multiple other users", "?userIds=" + firstUser + "," + secondUser, http.StatusOK, publicUsers},
		{"encoded query", "?userIds=" + firstUser + "%2C" + secondUser + "&cursor=a%2Bb", http.StatusOK, publicUsers},
		{"repeated parameter", "?userIds=" + firstUser + "&userIds=" + secondUser, http.StatusOK, publicUsers},
		{"missing userIds", "", http.StatusBadRequest, authError},
		{"empty userIds", "?userIds=", http.StatusBadRequest, authError},
		{"invalid UUID", "?userIds=not-a-uuid", http.StatusBadRequest, authError},
		{"Auth denies access", "?userIds=" + firstUser, http.StatusForbidden, authError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			type observedRequest struct {
				method string
				uri    string
				header http.Header
			}
			seen := make(chan observedRequest, 1)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen <- observedRequest{r.Method, r.URL.RequestURI(), r.Header.Clone()}
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Upstream", "auth")
				w.Header().Set("X-Request-Id", "untrusted-upstream-id")
				w.WriteHeader(tc.status)
				if _, err := io.WriteString(w, tc.body); err != nil {
					t.Errorf("write Auth response: %v", err)
				}
			}))
			defer upstream.Close()
			target, err := url.Parse(upstream.URL)
			if err != nil {
				t.Fatal(err)
			}
			authProxy, err := proxy.NewReverseProxy(target, proxy.RewriteAuth, proxy.HandleUpstreamError)
			if err != nil {
				t.Fatal(err)
			}
			verifier := &accessRouteVerifier{identity: requestcontext.Identity{UserID: httpTestUserID}}
			handler := newAccessRouteHandler(verifier, authProxy, http.NotFoundHandler())
			uri := "/api/v1/user" + tc.query
			request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, uri, nil)
			request.Header.Set("Authorization", "Bearer verified-token")
			request.Header.Set("X-User-Id", firstUser)
			request.Header.Set("X-Request-Id", "forged-request-id")
			request.Header.Set("Origin", "https://app.example")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != tc.status || response.Body.String() != tc.body {
				t.Errorf("response = (%d, %q), want (%d, %q)", response.Code, response.Body.String(), tc.status, tc.body)
			}
			for name, want := range map[string]string{
				"Content-Type":                     "application/json",
				"X-Upstream":                       "auth",
				"X-Request-Id":                     httpTestRequestID,
				"Access-Control-Allow-Origin":      "https://app.example",
				"Access-Control-Allow-Credentials": "true",
			} {
				if got := response.Header().Get(name); got != want {
					t.Errorf("response %s = %q, want %q", name, got, want)
				}
			}
			if verifier.calls != 1 || verifier.token != "verified-token" {
				t.Errorf("verifier calls = %d, token = %q", verifier.calls, verifier.token)
			}
			select {
			case got := <-seen:
				if got.method != http.MethodGet || got.uri != uri {
					t.Errorf("Auth request = %s %s, want GET %s", got.method, got.uri, uri)
				}
				for name, want := range map[string]string{
					"Authorization": "Bearer verified-token",
					"X-User-Id":     httpTestUserID,
					"X-Request-Id":  httpTestRequestID,
				} {
					if value := got.header.Get(name); value != want {
						t.Errorf("Auth %s = %q, want %q", name, value, want)
					}
				}
			default:
				t.Fatal("Auth was not called")
			}
		})
	}
}

func TestUserLookupPreflightBypassesAuthentication(t *testing.T) {
	t.Parallel()
	verifier := &accessRouteVerifier{}
	handler := newAccessRouteHandler(verifier, http.NotFoundHandler(), http.NotFoundHandler())
	request := httptest.NewRequestWithContext(t.Context(), http.MethodOptions, "/api/v1/user", nil)
	request.Header.Set("Origin", "https://app.example")
	request.Header.Set("Access-Control-Request-Method", http.MethodGet)
	request.Header.Set("Access-Control-Request-Headers", "Authorization")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || verifier.calls != 0 {
		t.Errorf("preflight status = %d, verifier calls = %d; want 204, 0", response.Code, verifier.calls)
	}
	if response.Header().Get("Access-Control-Allow-Origin") != "https://app.example" ||
		response.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Errorf("preflight CORS headers = %v", response.Header())
	}
}
