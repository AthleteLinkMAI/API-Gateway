package httpapi

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"gitlab.com/team-anonyms/athelete-link/api-gateway/internal/auth"
	"gitlab.com/team-anonyms/athelete-link/api-gateway/internal/observability"
	"gitlab.com/team-anonyms/athelete-link/api-gateway/internal/proxy"
)

const logTestUser = "123e4567-e89b-42d3-a456-426614174001"

type logDenylist struct {
	denied bool
	err    error
}

func (d logDenylist) IsDenied(context.Context, string) (bool, error) { return d.denied, d.err }

func logToken(t *testing.T) string {
	t.Helper()
	now := time.Now()
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub": logTestUser, "jti": "123e4567-e89b-42d3-a456-426614174002", "type": "ACCESS",
		"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Minute).Unix(),
	}).SignedString([]byte("log-test-key"))
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func loggingTestOptions(t *testing.T, target string, logs io.Writer, denylist logDenylist) HandlerOptions {
	t.Helper()
	verifier, err := auth.NewVerifier("log-test-key", denylist, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(target)
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
	readiness := &Readiness{}
	readiness.Set(true)
	return HandlerOptions{
		Readiness: readiness, CheckDependency: func(context.Context) error { return nil },
		CoreProxy: makeProxy(proxy.RewriteCore), AuthHandler: makeProxy(proxy.RewriteAuth),
		GameHandler: makeProxy(proxy.RewriteGame), Verifier: verifier,
		ProfileHandler: makeProxy(proxy.RewriteProfile), ChatHandler: makeProxy(proxy.RewriteChat),
		ProfileTimeout: time.Second, ChatTimeout: time.Second,
		CoreTimeout: time.Second, AuthTimeout: time.Second, GameTimeout: time.Second,
		WriteTimeout: 2 * time.Second, CORSOrigins: []string{"https://app.example"},
		NewRequestID: func() string { return "generated-request-id" },
		Logger:       observability.NewLogger(logs, slog.LevelDebug),
	}
}

func decodeRequestLog(t *testing.T, logs *bytes.Buffer) map[string]any {
	t.Helper()
	decoder := json.NewDecoder(logs)
	var result map[string]any
	if err := decoder.Decode(&result); err != nil {
		t.Fatalf("decode log: %v", err)
	}
	var extra map[string]any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		t.Fatalf("expected exactly one log record, got %v", err)
	}
	return result
}

func TestRequestLoggingAuthenticationAndErrors(t *testing.T) {
	for _, tc := range []struct {
		name, method, path, bearer, level, authResult, denylistResult, errorKind string
		lookup                                                                   logDenylist
		upstreamStatus, wantStatus                                               int
		wantCalled                                                               bool
	}{
		{name: "valid", method: "GET", path: "/api/v1/players", bearer: "valid", level: "INFO", authResult: "allowed", denylistResult: "clear", wantStatus: 200, wantCalled: true},
		{name: "missing bearer", method: "GET", path: "/api/v1/players", level: "WARN", authResult: "rejected", denylistResult: "not_checked", errorKind: "missing_bearer", wantStatus: 401},
		{name: "invalid token", method: "GET", path: "/api/v1/players", bearer: "secret-invalid-token", level: "WARN", authResult: "rejected", denylistResult: "not_checked", errorKind: "invalid_token", wantStatus: 401},
		{name: "revoked", method: "GET", path: "/api/v1/players", bearer: "valid", lookup: logDenylist{denied: true}, level: "WARN", authResult: "rejected", denylistResult: "denied", errorKind: "revoked_token", wantStatus: 401},
		{name: "fail open", method: "GET", path: "/api/v1/players", bearer: "valid", lookup: logDenylist{err: auth.ErrRedisUnavailable}, level: "WARN", authResult: "allowed_without_denylist", denylistResult: "unavailable", wantStatus: 200, wantCalled: true},
		{name: "command error", method: "GET", path: "/api/v1/players", bearer: "valid", lookup: logDenylist{err: errors.New("secret-redis-error")}, level: "ERROR", authResult: "rejected", denylistResult: "error", errorKind: "denylist_check_failed", wantStatus: 503},
		{name: "missing role", method: "GET", path: "/api/v1/report/all", bearer: "valid", level: "WARN", authResult: "allowed", denylistResult: "clear", errorKind: "role_missing_or_invalid", wantStatus: 403},
		{name: "unknown route", method: "GET", path: "/secret-path", level: "WARN", authResult: "not_required", denylistResult: "not_checked", errorKind: "route_not_found", wantStatus: 404},
		{name: "wrong method", method: "HEAD", path: "/api/v1/players", level: "WARN", authResult: "not_required", denylistResult: "not_checked", errorKind: "method_not_allowed", wantStatus: 405},
		{name: "upstream failure", method: "GET", path: "/api/v1/players", bearer: "valid", upstreamStatus: 500, level: "ERROR", authResult: "allowed", denylistResult: "clear", wantStatus: 500, wantCalled: true},
		{name: "public login", method: "POST", path: "/api/v1/auth/login", level: "INFO", authResult: "not_required", denylistResult: "not_checked", wantStatus: 200, wantCalled: true},
		{name: "health", method: "GET", path: "/healthz", level: "DEBUG", authResult: "not_required", denylistResult: "not_checked", wantStatus: 200},
		{name: "logout", method: "DELETE", path: "/api/v1/auth/logout", bearer: "valid", upstreamStatus: 204, level: "INFO", authResult: "allowed", denylistResult: "clear", wantStatus: 204, wantCalled: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				status := tc.upstreamStatus
				if status == 0 {
					status = http.StatusOK
				}
				w.Header().Set("X-Request-Id", "secret-upstream-request-id")
				w.WriteHeader(status)
				if status != http.StatusNoContent {
					if _, err := io.WriteString(w, "secret-response-body"); err != nil {
						t.Error(err)
					}
				}
			}))
			defer upstream.Close()
			var logs bytes.Buffer
			handler := NewHandler(loggingTestOptions(t, upstream.URL, &logs, tc.lookup))
			request := httptest.NewRequestWithContext(t.Context(), tc.method, tc.path+"?token=secret-query", strings.NewReader("secret-request-body"))
			request.Header.Set("X-User-Id", "secret-forged-user")
			request.Header.Set("X-Request-Id", "secret-forged-request-id")
			request.Header.Set("Cookie", "jwtRefreshToken=secret-cookie")
			bearer := tc.bearer
			if bearer == "valid" {
				bearer = logToken(t)
			}
			if bearer != "" {
				request.Header.Set("Authorization", "Bearer "+bearer)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, tc.wantStatus)
			}
			raw := logs.String()
			for _, secret := range []string{"secret-", bearer} {
				if secret != "" && strings.Contains(raw, secret) {
					t.Fatal("log leaked request or error content")
				}
			}
			entry := decodeRequestLog(t, &logs)
			for field, want := range map[string]any{
				"msg": "http_request_completed", "service": "api-gateway", "request_id": "generated-request-id",
				"level": tc.level, "status": float64(tc.wantStatus), "auth_result": tc.authResult,
				"denylist_result": tc.denylistResult, "upstream_called": tc.wantCalled,
			} {
				if entry[field] != want {
					t.Errorf("%s = %v, want %v", field, entry[field], want)
				}
			}
			if tc.errorKind != "" && entry["error_kind"] != tc.errorKind {
				t.Errorf("error_kind = %v, want %s", entry["error_kind"], tc.errorKind)
			}
			if tc.authResult == "allowed" || tc.authResult == "allowed_without_denylist" {
				if entry["user_id"] != logTestUser {
					t.Errorf("user_id = %v", entry["user_id"])
				}
			} else if _, exists := entry["user_id"]; exists {
				t.Error("log recorded an unverified user")
			}
			if tc.name == "logout" && entry["logout_refresh_cookie_present"] != true {
				t.Error("missing logout cookie presence")
			}
		})
	}
}

func TestCurrentUserRoutesUseJWTSubject(t *testing.T) {
	const otherUser = "123e4567-e89b-42d3-a456-426614174099"
	for _, tc := range []struct{ method, path, wantPath, upstream string }{
		{http.MethodGet, "/api/v1/players", "/api/v1/players/" + logTestUser, "game"},
		{http.MethodGet, "/api/v1/players/", "/api/v1/players/" + logTestUser, "game"},
		{http.MethodGet, "/api/v1/players/" + otherUser, "/api/v1/players/" + otherUser, "game"},
		{http.MethodGet, "/api/v1/user/me", "/api/v1/user/me", "profile"},
		{http.MethodPut, "/api/v1/user", "/api/v1/user", "profile"},
		{http.MethodPut, "/api/v1/user/password", "/api/v1/user/password", "auth"},
		{http.MethodPut, "/api/v1/user/email", "/api/v1/user/email", "auth"},
		{http.MethodDelete, "/api/v1/user", "/api/v1/user", "auth"},
		{http.MethodPost, "/api/v1/verification/email", "/api/v1/verification/email", "auth"},
		{http.MethodPost, "/api/v1/verification/send-email-verification-code", "/api/v1/verification/send-email-verification-code", "auth"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			seen := make(chan *http.Request, 1)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen <- r.Clone(context.WithoutCancel(r.Context()))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusAccepted)
				if _, err := io.WriteString(w, `{"unchanged":true}`); err != nil {
					t.Error(err)
				}
			}))
			defer upstream.Close()
			var logs bytes.Buffer
			handler := NewHandler(loggingTestOptions(t, upstream.URL, &logs, logDenylist{}))
			request := httptest.NewRequestWithContext(t.Context(), tc.method, tc.path+"?userId="+otherUser+"&cursor=abc%2Fdef", nil)
			token := logToken(t)
			request.Header.Set("Authorization", "Bearer "+token)
			request.Header.Set("X-User-Id", otherUser)
			request.Header.Set("Cookie", "jwtRefreshToken=secret-cookie")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != 202 || response.Body.String() != `{"unchanged":true}` {
				t.Fatalf("response = %d %s", response.Code, response.Body.String())
			}
			if tc.path == "/api/v1/user/me" {
				entry := decodeRequestLog(t, &logs)
				if entry["route"] != tc.path || entry["user_id"] != logTestUser || entry["upstream"] != "profile" {
					t.Errorf("current-user request log = %v", entry)
				}
			}
			got := <-seen
			identityHeader := "X-User-Id"
			if tc.path == "/api/v1/user/me" {
				identityHeader = "userId"
			}
			if got.URL.Path != tc.wantPath || got.URL.RawQuery != request.URL.RawQuery || got.Header.Get(identityHeader) != logTestUser {
				t.Errorf("upstream path/query/identity = %s %s %s", got.URL.Path, got.URL.RawQuery, got.Header.Get("X-User-Id"))
			}
			if got.Header.Get("X-Request-Id") != "generated-request-id" {
				t.Error("upstream lost request ID")
			}
			if tc.upstream == "auth" {
				if got.Header.Get("Authorization") != "Bearer "+token || got.Header.Get("Cookie") != request.Header.Get("Cookie") {
					t.Error("Auth credentials boundary changed")
				}
			} else if got.Header.Get("Authorization") != "" || got.Header.Get("Cookie") != "" {
				t.Error("Game received credentials")
			}
		})
	}
}

func TestLoggingWriterPreservesFlushAndDeadlines(t *testing.T) {
	var logs bytes.Buffer
	handler := withRequestLogging(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		controller := http.NewResponseController(w)
		if err := controller.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusEarlyHints)
		if err := controller.Flush(); err != nil {
			t.Error(err)
		}
		if _, err := io.WriteString(w, "stream"); err != nil {
			t.Error(err)
		}
	}), observability.NewLogger(&logs, slog.LevelDebug))
	writer := &deadlineLogWriter{header: make(http.Header)}
	handler.ServeHTTP(writer, httptest.NewRequestWithContext(t.Context(), "GET", "/api/v1/requests/secret-path", nil))
	if writer.deadline.IsZero() || !writer.flushed || writer.body.String() != "stream" {
		t.Fatal("writer capabilities were lost")
	}
	entry := decodeRequestLog(t, &logs)
	if entry["status"] != float64(200) || entry["response_bytes"] != float64(6) || entry["route"] != "/api/v1/requests/{id}" {
		t.Errorf("entry = %v", entry)
	}
}

type deadlineLogWriter struct {
	header   http.Header
	body     bytes.Buffer
	deadline time.Time
	flushed  bool
}

func (w *deadlineLogWriter) Header() http.Header         { return w.header }
func (w *deadlineLogWriter) WriteHeader(int)             {}
func (w *deadlineLogWriter) Write(b []byte) (int, error) { return w.body.Write(b) }
func (w *deadlineLogWriter) Flush()                      { w.flushed = true }
func (w *deadlineLogWriter) SetWriteDeadline(deadline time.Time) error {
	w.deadline = deadline
	return nil
}

func TestLoggingCanceledAndAbortedRequests(t *testing.T) {
	for _, tc := range []struct {
		name, kind, level string
		abort             bool
	}{
		{"canceled", "client_canceled", "INFO", false},
		{"panic", "handler_aborted", "ERROR", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			handler := withRequestLogging(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				if tc.abort {
					panic(http.ErrAbortHandler)
				}
				cancel()
			}), observability.NewLogger(&logs, slog.LevelDebug))
			func() {
				defer func() {
					if got := recover(); tc.abort {
						err, ok := got.(error)
						if !ok || !errors.Is(err, http.ErrAbortHandler) {
							t.Errorf("panic = %v", got)
						}
					}
				}()
				handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(ctx, "GET", "/api/v1/players", nil))
			}()
			entry := decodeRequestLog(t, &logs)
			if entry["status"] != float64(0) || entry["error_kind"] != tc.kind || entry["level"] != tc.level {
				t.Errorf("entry = %v", entry)
			}
		})
	}
}

func TestRequestLoggingTransportFailures(t *testing.T) {
	for _, tc := range []struct {
		name, kind string
		status     int
	}{
		{"connection failure", "connection_failed", http.StatusBadGateway},
		{"timeout", "upstream_timeout", http.StatusGatewayTimeout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				<-r.Context().Done()
			}))
			defer upstream.Close()
			if tc.status == http.StatusBadGateway {
				upstream.Close()
			}
			var logs bytes.Buffer
			options := loggingTestOptions(t, upstream.URL, &logs, logDenylist{})
			options.GameTimeout = 50 * time.Millisecond
			handler := NewHandler(options)
			request := httptest.NewRequestWithContext(t.Context(), "GET", "/api/v1/players", nil)
			request.Header.Set("Authorization", "Bearer "+logToken(t))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			entry := decodeRequestLog(t, &logs)
			if response.Code != tc.status || entry["error_kind"] != tc.kind || entry["level"] != "ERROR" || entry["upstream_called"] != true {
				t.Errorf("response = %d, entry = %v", response.Code, entry)
			}
		})
	}
}

func TestSuccessfulBackgroundRequestsRequireDebug(t *testing.T) {
	var logs bytes.Buffer
	options := loggingTestOptions(t, "http://127.0.0.1:1", &logs, logDenylist{})
	options.Logger = observability.NewLogger(&logs, slog.LevelInfo)
	handler := NewHandler(options)
	for _, path := range []string{"/healthz", "/readyz", "/openapi.yaml", "/swagger/"} {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), "GET", path, nil))
	}
	preflight := httptest.NewRequestWithContext(t.Context(), "OPTIONS", "/api/v1/user/me", nil)
	preflight.Header.Set("Origin", "https://app.example")
	preflight.Header.Set("Access-Control-Request-Method", "GET")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, preflight)
	if response.Code != http.StatusNoContent || logs.Len() != 0 {
		t.Fatalf("preflight = %d, logs = %s", response.Code, logs.String())
	}
	options.Readiness.Set(false)
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), "GET", "/readyz", nil))
	entry := decodeRequestLog(t, &logs)
	if entry["level"] != "ERROR" || entry["error_kind"] != "not_ready" {
		t.Errorf("entry = %v", entry)
	}
}

func TestRequestLoggingIncludesRequestIDFailure(t *testing.T) {
	var logs bytes.Buffer
	options := loggingTestOptions(t, "http://127.0.0.1:1", &logs, logDenylist{})
	options.NewRequestID = func() string { return "" }
	response := httptest.NewRecorder()
	NewHandler(options).ServeHTTP(response, httptest.NewRequestWithContext(t.Context(), "GET", "/api/v1/players", nil))
	entry := decodeRequestLog(t, &logs)
	if response.Code != 500 || entry["error_kind"] != "request_id_failed" || entry["upstream_called"] != false {
		t.Errorf("entry = %v", entry)
	}
}

func TestProxyStreamingWithRequestLogging(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		if _, err := io.WriteString(w, "first\n"); err != nil {
			t.Error(err)
			return
		}
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Error(err)
			return
		}
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		if _, err := io.WriteString(w, "second\n"); err != nil {
			t.Error(err)
		}
	}))
	defer upstream.Close()
	var logs bytes.Buffer
	options := loggingTestOptions(t, upstream.URL, &logs, logDenylist{})
	gateway := httptest.NewServer(NewHandler(options))
	defer gateway.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, "GET", gateway.URL+"/api/v1/players", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+logToken(t))
	response, err := gateway.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	reader := bufio.NewReader(response.Body)
	first, err := reader.ReadString('\n')
	close(release)
	if err != nil || first != "first\n" {
		t.Fatalf("first streamed chunk = %q, %v", first, err)
	}
	rest, err := io.ReadAll(reader)
	if err != nil || string(rest) != "second\n" {
		t.Fatalf("remaining body = %q, %v", rest, err)
	}
	entry := decodeRequestLog(t, &logs)
	if entry["response_bytes"] != float64(len(first)+len(rest)) || entry["status"] != float64(200) {
		t.Errorf("entry = %v", entry)
	}
}

func (d logDenylist) IsBanned(context.Context, string) (bool, error) { return false, nil }
