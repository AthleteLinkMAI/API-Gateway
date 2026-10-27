package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"gitlab.com/team-anonyms/athelete-link/api-gateway/internal/auth"
)

const (
	acceptanceUserID = "123e4567-e89b-42d3-a456-426614174001"
	acceptanceJTI    = "123e4567-e89b-42d3-a456-426614174002"
	acceptanceKey    = "http-acceptance-test-only-key"
)

// Stub only the Redis command boundary: classification, JWT verification,
// HTTP middleware, and the upstream HTTP request use production code.
type acceptanceRedis struct {
	t     *testing.T
	count int64
	err   error
	calls atomic.Int32
}

func (r *acceptanceRedis) Exists(ctx context.Context, keys ...string) *redis.IntCmd {
	r.calls.Add(1)
	if !slices.Equal(keys, []string{"jwt:denylist:" + acceptanceJTI}) {
		r.t.Errorf("Redis keys = %q, want exact token denylist key", keys)
	}
	if err := ctx.Err(); err != nil {
		return redis.NewIntResult(0, err)
	}
	return redis.NewIntResult(r.count, r.err)
}

type acceptanceRedisCommandError string

func (e acceptanceRedisCommandError) Error() string { return string(e) }
func (acceptanceRedisCommandError) RedisError()     {}

func TestCoreHTTPJWTAndRedisBoundary(t *testing.T) {
	now := time.Date(2026, time.September, 29, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name       string
		change     func(jwt.MapClaims)
		method     jwt.SigningMethod
		wrongKey   bool
		missing    bool
		duplicate  bool
		malformed  bool
		denied     int64
		redisErr   error
		wantStatus int
		wantLookup int32
		wantCore   int32
	}{
		{name: "valid JWT", wantStatus: 204, wantLookup: 1, wantCore: 1},
		{name: "missing JWT", missing: true, wantStatus: 401},
		{name: "malformed JWT", malformed: true, wantStatus: 401},
		{name: "duplicate authorization", duplicate: true, wantStatus: 401},
		{name: "wrong signature", wrongKey: true, wantStatus: 401},
		{name: "wrong algorithm", method: jwt.SigningMethodHS256, wantStatus: 401},
		{name: "refresh token", change: func(c jwt.MapClaims) { c["type"] = "REFRESH" }, wantStatus: 401},
		{name: "invalid user UUID", change: func(c jwt.MapClaims) { c["sub"] = "forged-user" }, wantStatus: 401},
		{name: "invalid token UUID", change: func(c jwt.MapClaims) { c["jti"] = "invalid" }, wantStatus: 401},
		{name: "missing issued at", change: func(c jwt.MapClaims) { delete(c, "iat") }, wantStatus: 401},
		{name: "missing expiration", change: func(c jwt.MapClaims) { delete(c, "exp") }, wantStatus: 401},
		{name: "expires now", change: func(c jwt.MapClaims) { c["exp"] = now.Unix() }, wantStatus: 401},
		{name: "issued in future", change: func(c jwt.MapClaims) { c["iat"] = now.Add(time.Second).Unix() }, wantStatus: 401},
		{name: "denylist hit", denied: 1, wantStatus: 401, wantLookup: 1},
		{name: "Redis connection refused", redisErr: syscall.ECONNREFUSED, wantStatus: 204, wantLookup: 1, wantCore: 1},
		{name: "Redis lookup timeout", redisErr: context.DeadlineExceeded, wantStatus: 204, wantLookup: 1, wantCore: 1},
		{name: "Redis command error", redisErr: acceptanceRedisCommandError("ERR command failed"), wantStatus: 503, wantLookup: 1},
		{name: "unclassified Redis error", redisErr: errors.New("unclassified lookup failure"), wantStatus: 503, wantLookup: 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			redisStub := &acceptanceRedis{t: t, count: tc.denied, err: tc.redisErr}
			verifier, err := auth.NewVerifier(acceptanceKey, auth.NewRedisDenylist(redisStub), func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			var coreCalls atomic.Int32
			core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				coreCalls.Add(1)
				if values := r.Header.Values("X-User-Id"); !slices.Equal(values, []string{acceptanceUserID}) {
					t.Errorf("Core identity = %q, want verified JWT subject", values)
				}
				if values := r.Header.Values("X-Request-Id"); !slices.Equal(values, []string{"gateway-request-id"}) {
					t.Errorf("Core request ID = %q, want Gateway ID", values)
				}
				if values := r.Header.Values("Authorization"); len(values) != 0 {
					t.Error("Core received the access token")
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			t.Cleanup(core.Close)
			gateway := httptest.NewServer(newCoreProxyHandler(t, core.URL, time.Second, 2*time.Second, verifier))
			t.Cleanup(gateway.Close)

			claims := jwt.MapClaims{
				"sub": acceptanceUserID, "jti": acceptanceJTI, "type": "ACCESS",
				"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Minute).Unix(),
			}
			if tc.change != nil {
				tc.change(claims)
			}
			method := tc.method
			if method == nil {
				method = jwt.SigningMethodHS512
			}
			key := acceptanceKey
			if tc.wrongKey {
				key = "another-test-only-key"
			}
			token, err := jwt.NewWithClaims(method, claims).SignedString([]byte(key))
			if err != nil {
				t.Fatal(err)
			}
			if tc.malformed {
				token = "not-a-jwt"
			}
			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, gateway.URL+"/api/v1/sports", nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("X-User-Id", "forged-user")
			request.Header.Set("X-Request-Id", "client-request-id")
			if !tc.missing {
				request.Header.Set("Authorization", "Bearer "+token)
			}
			if tc.duplicate {
				request.Header.Add("Authorization", "Bearer "+token)
			}
			client := &http.Client{Timeout: 3 * time.Second}
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			_, readErr := io.Copy(io.Discard, response.Body)
			if err := response.Body.Close(); err != nil {
				t.Errorf("close response body: %v", err)
			}
			if readErr != nil {
				t.Fatal(readErr)
			}
			if response.StatusCode != tc.wantStatus {
				t.Errorf("status = %d, want %d", response.StatusCode, tc.wantStatus)
			}
			if values := response.Header.Values("X-Request-Id"); !slices.Equal(values, []string{"gateway-request-id"}) {
				t.Errorf("response request ID = %q, want Gateway ID", values)
			}
			if got := redisStub.calls.Load(); got != tc.wantLookup {
				t.Errorf("Redis calls = %d, want %d", got, tc.wantLookup)
			}
			if got := coreCalls.Load(); got != tc.wantCore {
				t.Errorf("Core calls = %d, want %d", got, tc.wantCore)
			}
		})
	}
}

func TestCoreHTTPResponsePassthrough(t *testing.T) {
	tests := []struct {
		name   string
		method string
		uri    string
		status int
		body   string
	}{
		{"created", http.MethodPost, "/api/v1/requests?z=1&z=2&raw=%2F", 201, `{"id":"new"}`},
		{"user request list", http.MethodGet, "/api/v1/requests/users/123?statuses=COMPLETED&page=0", 202, "accepted"},
		{"unexpected success and binary body", http.MethodPut, "/api/v1/requests/%31", 207, "\x00\xff\r\nopaque"},
		{"empty success", http.MethodPost, "/api/v1/requests/123/cancel", 204, ""},
		{"redirect", http.MethodGet, "/api/v1/sports", 302, "redirect from Core"},
		{"bad request", http.MethodPut, "/api/v1/requests/123?empty=&x=1+x", 400, "not JSON\n"},
		{"Core authentication error", http.MethodGet, "/api/v1/sports?", 401, "Core rejected the request"},
		{"Core authorization error", http.MethodPost, "/api/v1/requests/123/start", 403, `{"code":"FORBIDDEN"}`},
		{"Core not found", http.MethodGet, "/api/v1/requests/absent", 404, `{"code":"NOT_FOUND"}`},
		{"Core conflict", http.MethodPost, "/api/v1/requests/123/join", 409, `{"code":"CONFLICT","details":{"a":1}}`},
		{"Core validation error", http.MethodPut, "/api/v1/requests/123", 422, "invalid payload"},
		{"Core failure", http.MethodGet, "/api/v1/requests", 500, "Core internal error\n"},
	}
	type observedRequest struct {
		method string
		uri    string
		body   string
	}
	observed := make(chan observedRequest, len(tests)+1)
	var coreCalls atomic.Int32
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		coreCalls.Add(1)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read Core request: %v", err)
		}
		select {
		case observed <- observedRequest{r.Method, r.URL.RequestURI(), string(body)}:
		default:
			t.Error("unexpected extra Core request")
		}
		for _, tc := range tests {
			if r.Header.Get("X-Test-Case") != tc.name {
				continue
			}
			// A proxy following this redirect would make a second upstream call.
			if r.URL.Path == "/redirect-target" {
				w.WriteHeader(http.StatusTeapot)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("ETag", `"core-etag"`)
			w.Header().Add("X-Core-Value", "first")
			w.Header().Add("X-Core-Value", "second")
			if tc.status == http.StatusFound {
				w.Header().Set("Location", "/redirect-target")
			}
			w.WriteHeader(tc.status)
			writeTestString(t, w, tc.body)
			return
		}
		http.Error(w, "unexpected request", http.StatusTeapot)
	}))
	t.Cleanup(core.Close)
	gatewayURL, token, client := startGatewayWithCore(t, core.URL)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			const requestBody = "opaque request\x00\xff\n"
			before := coreCalls.Load()
			request, err := http.NewRequestWithContext(t.Context(), tc.method, gatewayURL+tc.uri, strings.NewReader(requestBody))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Authorization", "Bearer "+token)
			request.Header.Set("X-Test-Case", tc.name)
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			body, readErr := io.ReadAll(response.Body)
			if err := response.Body.Close(); err != nil {
				t.Errorf("close response body: %v", err)
			}
			if readErr != nil {
				t.Fatal(readErr)
			}
			if response.StatusCode != tc.status || string(body) != tc.body {
				t.Errorf("response = (%d, %q), want (%d, %q)", response.StatusCode, body, tc.status, tc.body)
			}
			if response.Header.Get("Content-Type") != "application/octet-stream" || response.Header.Get("ETag") != `"core-etag"` {
				t.Error("ordinary Core response headers changed")
			}
			if values := response.Header.Values("X-Core-Value"); !slices.Equal(values, []string{"first", "second"}) {
				t.Errorf("repeated response header = %q", values)
			}
			if tc.status == http.StatusFound && response.Header.Get("Location") != "/redirect-target" {
				t.Errorf("Location = %q, want Core redirect", response.Header.Get("Location"))
			}
			if got := coreCalls.Load() - before; got != 1 {
				t.Errorf("Core calls = %d, want exactly one", got)
			}
			select {
			case got := <-observed:
				if got.method != tc.method || got.uri != tc.uri || got.body != requestBody {
					t.Errorf("Core request = %#v, want %s %s with original body", got, tc.method, tc.uri)
				}
			default:
				t.Error("Core did not observe request")
			}
		})
	}
}
