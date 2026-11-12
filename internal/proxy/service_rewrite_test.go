package proxy_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gitlab.com/team-anonyms/athelete-link/api-gateway/internal/proxy"
	"gitlab.com/team-anonyms/athelete-link/api-gateway/internal/requestcontext"
)

func writeTestString(t *testing.T, w io.Writer, value string) {
	t.Helper()
	if _, err := io.WriteString(w, value); err != nil {
		t.Errorf("write response: %v", err)
	}
}

func closeTestBody(t *testing.T, body io.Closer) {
	t.Helper()
	if err := body.Close(); err != nil {
		t.Errorf("close response body: %v", err)
	}
}

func TestServiceRewritesKeepTransportAndTrustBoundary(t *testing.T) {
	t.Parallel()

	const userID = "123e4567-e89b-42d3-a456-426614174001"
	const requestID = "gateway-request-id"
	const requestBody = `{"value":"unchanged"}`

	tests := []struct {
		name              string
		rewrite           proxy.RewriteFunc
		method            string
		path              string
		verified          bool
		wantAuthorization string
		wantCookie        string
		wantUserID        string
	}{
		{
			name:       "public Auth keeps cookie but drops unverified bearer",
			rewrite:    proxy.RewriteAuth,
			method:     http.MethodPost,
			path:       "/api/v1/auth/refresh?cursor=a%2Bb&limit=20",
			wantCookie: "refreshToken=client-cookie",
		},
		{
			name:              "protected Auth sends verified bearer and user",
			rewrite:           proxy.RewriteAuth,
			method:            http.MethodPut,
			path:              "/api/v1/user/email/%31?cursor=a%2Bb&limit=20",
			verified:          true,
			wantAuthorization: "Bearer verified-token",
			wantCookie:        "refreshToken=client-cookie",
			wantUserID:        userID,
		},
		{
			name:       "Game sends caller identity without bearer or cookie",
			rewrite:    proxy.RewriteGame,
			method:     http.MethodGet,
			path:       "/api/v1/players/another-user/matches?cursor=a%2Bb&limit=20",
			verified:   true,
			wantUserID: userID,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			type observed struct {
				method string
				uri    string
				header http.Header
				body   string
				err    error
			}
			seen := make(chan observed, 1)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				seen <- observed{r.Method, r.URL.RequestURI(), r.Header.Clone(), string(body), err}
				w.Header().Set("X-Request-Id", "upstream-request-id")
				w.Header().Set("Access-Control-Allow-Origin", "https://upstream.example")
				w.Header().Set("X-Upstream", "response")
				w.Header().Add("Set-Cookie", "refreshToken=new; HttpOnly")
				w.Header().Add("Set-Cookie", "session=second; Secure")
				w.WriteHeader(http.StatusBadRequest)
				writeTestString(t, w, "upstream error\n")
			}))
			defer upstream.Close()

			reverseProxy := mustReverseProxy(t, upstream.URL, tc.rewrite)
			ctx := requestcontext.WithRequestID(context.Background(), requestID)
			if tc.verified {
				ctx = requestcontext.WithIdentity(ctx, requestcontext.Identity{UserID: userID})
				ctx = requestcontext.WithVerifiedAccessToken(ctx, "verified-token")
			}
			request := httptest.NewRequestWithContext(
				ctx, tc.method, "http://gateway.test"+tc.path, strings.NewReader(requestBody),
			)
			request.Header.Set("Authorization", "Bearer client-token")
			request.Header.Set("Cookie", "refreshToken=client-cookie")
			request.Header.Set("X-User-Id", "forged-user")
			request.Header.Set("X-Request-Id", "client-request-id")
			request.Header.Set("Forwarded", "for=untrusted")
			request.Header.Set("X-Forwarded-For", "untrusted")
			request.Header.Set("X-Real-Ip", "untrusted")
			request.Header.Set("X-Ordinary", "keep-me")

			recorder := httptest.NewRecorder()
			reverseProxy.ServeHTTP(recorder, request)
			response := recorder.Result()
			defer closeTestBody(t, response.Body)
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			if response.StatusCode != http.StatusBadRequest || string(body) != "upstream error\n" {
				t.Errorf("response = (%d, %q), want (400, upstream body)", response.StatusCode, body)
			}
			if got := response.Header.Get("X-Upstream"); got != "response" {
				t.Errorf("X-Upstream = %q, want response", got)
			}
			if got := response.Header.Values("Set-Cookie"); len(got) != 2 ||
				got[0] != "refreshToken=new; HttpOnly" || got[1] != "session=second; Secure" {
				t.Errorf("Set-Cookie = %q, want both upstream values", got)
			}
			for _, name := range []string{"X-Request-Id", "Access-Control-Allow-Origin"} {
				if got := response.Header.Get(name); got != "" {
					t.Errorf("response %s = %q, want empty", name, got)
				}
			}

			got := <-seen
			if got.err != nil {
				t.Fatalf("read upstream body: %v", got.err)
			}
			if got.method != tc.method || got.uri != tc.path || got.body != requestBody {
				t.Errorf("upstream request = (%s, %s, %q), want (%s, %s, %q)",
					got.method, got.uri, got.body, tc.method, tc.path, requestBody)
			}
			for name, want := range map[string]string{
				"Authorization": tc.wantAuthorization,
				"Cookie":        tc.wantCookie,
				"X-User-Id":     tc.wantUserID,
				"X-Request-Id":  requestID,
				"X-Ordinary":    "keep-me",
			} {
				if value := got.header.Get(name); value != want {
					t.Errorf("upstream %s = %q, want %q", name, value, want)
				}
			}
			for _, name := range []string{"Forwarded", "X-Forwarded-For", "X-Real-Ip"} {
				if value := got.header.Get(name); value != "" {
					t.Errorf("upstream %s = %q, want empty", name, value)
				}
			}
		})
	}
}
