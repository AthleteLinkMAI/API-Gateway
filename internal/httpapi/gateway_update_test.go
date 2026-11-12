package httpapi_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"gitlab.com/team-anonyms/athelete-link/api-gateway/internal/auth"
	"gitlab.com/team-anonyms/athelete-link/api-gateway/internal/httpapi"
	"gitlab.com/team-anonyms/athelete-link/api-gateway/internal/proxy"
)

type featureStore struct {
	denied, banned  bool
	denyErr, banErr error
	calls           int
}

func (s *featureStore) IsDenied(context.Context, string) (bool, error) {
	s.calls++
	return s.denied, s.denyErr
}
func (s *featureStore) IsBanned(context.Context, string) (bool, error) {
	s.calls++
	return s.banned, s.banErr
}

func featureToken(t *testing.T, role any) string {
	t.Helper()
	now := time.Now()
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub": httpTestUserID, "jti": httpTestTokenID, "type": "ACCESS", "role": role,
		"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Minute).Unix(),
	}).SignedString([]byte(httpTestSecret))
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func featureHandler(t *testing.T, store *featureStore, upstream http.Handler) http.Handler {
	t.Helper()
	verifier, err := auth.NewVerifier(httpTestSecret, store, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	target := httptest.NewServer(upstream)
	t.Cleanup(target.Close)
	u, err := url.Parse(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	makeProxy := func(rewrite proxy.RewriteFunc) http.Handler {
		p, err := proxy.NewReverseProxy(u, rewrite, proxy.HandleUpstreamError)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	return httpapi.NewHandler(httpapi.HandlerOptions{
		CheckDependency: func(context.Context) error { return nil }, Readiness: &httpapi.Readiness{},
		CoreProxy: makeProxy(proxy.RewriteCore), AuthHandler: makeProxy(proxy.RewriteAuth), GameHandler: makeProxy(proxy.RewriteGame),
		ProfileHandler: makeProxy(proxy.RewriteProfile), ChatHandler: makeProxy(proxy.RewriteChat),
		CoreTimeout: time.Second, AuthTimeout: time.Second, GameTimeout: time.Second, ProfileTimeout: time.Second, ChatTimeout: time.Second,
		WriteTimeout: 2 * time.Second, Verifier: verifier, NewRequestID: func() string { return httpTestRequestID },
	})
}

func TestPublicOperationsValidateOptionalBearer(t *testing.T) {
	for _, path := range []string{"/api/v1/user", "/api/v1/auth/login", "/api/v1/auth/refresh", "/api/v1/verification/send-password-reset-code", "/api/v1/verification/password-reset"} {
		for _, tc := range []struct {
			name, authorization string
			denied, banned      bool
			lookupErr           error
			want, calls         int
		}{
			{name: "anonymous", want: 202},
			{name: "valid", authorization: "valid", want: 202, calls: 2},
			{name: "invalid", authorization: "Bearer invalid", want: 401},
			{name: "empty", authorization: "empty", want: 401},
			{name: "revoked", authorization: "valid", denied: true, want: 401, calls: 2},
			{name: "banned", authorization: "valid", banned: true, want: 403, calls: 2},
			{name: "Redis unavailable", authorization: "valid", lookupErr: auth.ErrRedisUnavailable, want: 202, calls: 2},
			{name: "Redis command failure", authorization: "valid", lookupErr: errors.New("ERR"), want: 503, calls: 2},
		} {
			t.Run(path+"/"+tc.name, func(t *testing.T) {
				store := &featureStore{denied: tc.denied, banned: tc.banned, denyErr: tc.lookupErr, banErr: tc.lookupErr}
				upstreamCalls := 0
				handler := featureHandler(t, store, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					upstreamCalls++
					if r.Header.Get("X-User-Role") != "" || r.Header.Get("userId") != "" {
						t.Error("forged identity header reached Auth")
					}
					wantID := ""
					if tc.authorization == "valid" {
						wantID = httpTestUserID
					}
					if r.Header.Get("X-User-Id") != wantID {
						t.Errorf("identity=%q", r.Header.Get("X-User-Id"))
					}
					w.WriteHeader(202)
				}))
				req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, nil)
				req.Header.Set("X-User-Id", "forged")
				req.Header.Set("X-User-Role", "ADMIN")
				req.Header.Set("userId", "forged")
				switch tc.authorization {
				case "valid":
					req.Header.Set("Authorization", "Bearer "+featureToken(t, "USER"))
				case "empty":
					req.Header["Authorization"] = []string{""}
				case "":
				default:
					req.Header.Set("Authorization", tc.authorization)
				}
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, req)
				wantUpstream := 0
				if tc.want == 202 {
					wantUpstream = 1
				}
				if response.Code != tc.want || store.calls != tc.calls || upstreamCalls != wantUpstream {
					t.Fatalf("status=%d checks=%d upstream=%d", response.Code, store.calls, upstreamCalls)
				}
			})
		}
	}
}

func TestTrustedHeadersAndPayloadAcrossServices(t *testing.T) {
	for _, tc := range []struct {
		method, path, wantPath, idHeader string
		roleRequired                     bool
	}{
		{"PUT", "/api/v1/user", "/api/v1/user", "X-User-Id", false},
		{"GET", "/api/v1/user/me", "/api/v1/user/me", "userId", false},
		{"PUT", "/api/v1/user/role", "/api/v1/user/role", "X-User-Id", true},
		{"POST", "/api/v1/ban", "/api/v1/ban", "X-User-Id", true},
		{"GET", "/api/v1/ban/a%2Bb%40example.com", "/api/v1/ban/a%2Bb%40example.com", "X-User-Id", false},
		{"POST", "/api/v1/message/chat", "/api/v1/message/chat", "X-User-Id", false},
		{"GET", "/api/v1/report/all", "/api/v1/report/all", "X-User-Id", true},
		{"DELETE", "/api/v1/report/other-user", "/api/v1/report/other-user", "X-User-Id", true},
		{"POST", "/api/v1/results", "/api/v1/results", "X-User-Id", false},
		{"POST", "/api/v1/requests/request/join-requests/participant/decision", "/api/v1/requests/request/join-requests/participant/decision", "X-User-Id", false},
		{"GET", "/api/v1/players", "/api/v1/players/" + httpTestUserID, "X-User-Id", false},
		{"GET", "/api/v1/players/", "/api/v1/players/" + httpTestUserID, "X-User-Id", false},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			const body = `{"userId":"target-user","senderId":"payload-sender"}`
			const query = "dto=%7B%22recordedBy%22%3A%22target%22%7D&userId=target"
			calls := 0
			handler := featureHandler(t, &featureStore{}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				actual, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
				}
				if r.Method != tc.method || r.URL.EscapedPath() != tc.wantPath || r.URL.RawQuery != query || string(actual) != body {
					t.Errorf("upstream=%s %s %q", r.Method, r.URL.RequestURI(), actual)
				}
				for _, name := range []string{"userId", "X-User-Id", "X-User-Role"} {
					want := ""
					if name == tc.idHeader {
						want = httpTestUserID
					}
					if name == "X-User-Role" && tc.roleRequired {
						want = "MODERATOR"
					}
					if r.Header.Get(name) != want {
						t.Errorf("%s=%q, want %q", name, r.Header.Get(name), want)
					}
				}
				if r.Header.Get("X-Request-Id") != httpTestRequestID {
					t.Error("missing trusted request ID")
				}
				w.WriteHeader(202)
			}))
			req := httptest.NewRequestWithContext(t.Context(), tc.method, tc.path+"?"+query, strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+featureToken(t, "MODERATOR"))
			req.Header.Set("X-User-Id", "forged")
			req.Header.Set("userId", "forged")
			req.Header.Set("X-User-Role", "ADMIN")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			if response.Code != 202 || calls != 1 {
				t.Fatalf("status=%d calls=%d", response.Code, calls)
			}
		})
	}
}

func TestRoleRequiredOnlyOnDeclaredOperations(t *testing.T) {
	for _, role := range []any{nil, "OWNER", 123, "ADMIN", "MODERATOR", "USER"} {
		for _, path := range []string{"/api/v1/report/all", "/api/v1/players"} {
			t.Run(path+"/"+fmt.Sprint(role), func(t *testing.T) {
				handler := featureHandler(t, &featureStore{}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(202) }))
				req := httptest.NewRequestWithContext(t.Context(), "GET", path, nil)
				req.Header.Set("Authorization", "Bearer "+featureToken(t, role))
				req.Header.Set("X-User-Role", "ADMIN")
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, req)
				want := 202
				valid := role == "ADMIN" || role == "MODERATOR" || role == "USER"
				if path == "/api/v1/report/all" && !valid {
					want = 403
				}
				if response.Code != want {
					t.Errorf("status=%d want=%d", response.Code, want)
				}
			})
		}
	}
}
