package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestCoreProxyTrustedHeaderBoundary(t *testing.T) {
	const (
		userID        = "123e4567-e89b-42d3-a456-426614174001"
		tokenID       = "123e4567-e89b-42d3-a456-426614174002"
		secret        = "gateway-boundary-test-signing-key"
		requestURI    = "/api/v1/requests/%31/start?z=1&z=2&raw=%2F"
		requestBody   = `{"title":"training"}`
		clientID      = "client-supplied-id"
		coreID        = "core-supplied-id"
		coreCORS      = "https://untrusted-core.example"
		allowedOrigin = "https://allowed.example"
		customHeader  = "ordinary-header-value"
	)

	type observedRequest struct {
		method string
		uri    string
		body   string
		header http.Header
		err    error
	}

	observed := make(chan observedRequest, 2)
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		observed <- observedRequest{
			method: r.Method,
			uri:    r.URL.RequestURI(),
			body:   string(body),
			header: r.Header.Clone(),
			err:    err,
		}

		w.Header().Set("X-Core-Header", "preserved")
		w.Header().Set("X-Request-Id", coreID)
		w.Header().Set("Access-Control-Allow-Origin", coreCORS)
		w.Header().Set("Access-Control-Allow-Credentials", "false")
		w.Header().Set("Access-Control-Expose-Headers", "X-Core-Header")
		if r.Header.Get("X-Scenario") == "business-error" {
			w.WriteHeader(http.StatusConflict)
			writeTestString(t, w, `{"code":"CONFLICT"}`)
			return
		}
		w.WriteHeader(http.StatusCreated)
		writeTestString(t, w, `{"id":"created"}`)
	}))
	defer core.Close()

	httpAddr := unusedTCPAddress(t)
	redisAddr := unusedTCPAddress(t)
	t.Setenv("GATEWAY_HTTP_ADDR", httpAddr)
	setRequiredServiceURLsForTest(t, core.URL)
	t.Setenv("GATEWAY_CORE_TIMEOUT", "3s")
	t.Setenv("GATEWAY_WRITE_TIMEOUT", "5s")
	t.Setenv("GATEWAY_CORS_ORIGINS", allowedOrigin)
	t.Setenv("REDIS_ADDR", redisAddr)
	t.Setenv("JWT_SECRET", secret)
	t.Setenv("GATEWAY_SHUTDOWN_TIMEOUT", "1s")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runWithContext(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("shut down Gateway: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Gateway did not shut down")
		}
	})

	client := &http.Client{Timeout: 10 * time.Second}
	waitForGatewayStart(t, client, httpAddr)

	now := time.Now()
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub":  userID,
		"jti":  tokenID,
		"type": "ACCESS",
		"iat":  now.Add(-time.Minute).Unix(),
		"exp":  now.Add(time.Hour).Unix(),
	}).SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign access token: %v", err)
	}

	var previousID string
	for _, tc := range []struct {
		name       string
		scenario   string
		origin     string
		wantStatus int
		wantBody   string
		wantOrigin string
	}{
		{"Core success", "success", allowedOrigin, http.StatusCreated, `{"id":"created"}`, allowedOrigin},
		{"Core business error", "business-error", allowedOrigin, http.StatusConflict, `{"code":"CONFLICT"}`, allowedOrigin},
		{"foreign origin", "success", "https://foreign.example", http.StatusCreated, `{"id":"created"}`, ""},
		{"no origin", "success", "", http.StatusCreated, `{"id":"created"}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+httpAddr+requestURI, strings.NewReader(requestBody))
			if err != nil {
				t.Fatalf("create request: %v", err)
			}
			req.Header.Set("Authorization", "Bearer "+token)
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			req.Header.Set("Cookie", "session=client-cookie")
			req.Header.Set("X-User-Id", "forged-user")
			req.Header.Set("X-Request-Id", clientID)
			req.Header.Set("Forwarded", "for=192.0.2.1;proto=https")
			req.Header.Set("X-Forwarded-For", "192.0.2.1")
			req.Header.Set("X-Forwarded-Host", "forged.example")
			req.Header.Set("X-Forwarded-Proto", "https")
			req.Header.Set("X-Real-Ip", "192.0.2.1")
			req.Header.Set("X-Custom", customHeader)
			req.Header.Set("X-Scenario", tc.scenario)
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("call Gateway: %v", err)
			}
			body, readErr := io.ReadAll(resp.Body)
			closeErr := resp.Body.Close()
			if readErr != nil || closeErr != nil {
				t.Fatalf("read response: %v; close response: %v", readErr, closeErr)
			}

			var got observedRequest
			select {
			case got = <-observed:
			case <-time.After(4 * time.Second):
				t.Fatal("Core did not receive request")
			}
			if got.err != nil {
				t.Fatalf("Core read body: %v", got.err)
			}
			if got.method != http.MethodPost || got.uri != requestURI || got.body != requestBody {
				t.Errorf("Core received method=%q URI=%q body=%q", got.method, got.uri, got.body)
			}
			for _, name := range []string{
				"Authorization", "Cookie", "Forwarded", "X-Forwarded-For",
				"X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-Ip",
			} {
				if values := got.header.Values(name); len(values) != 0 {
					t.Errorf("Core received untrusted %s: %q", name, values)
				}
			}
			if values := got.header.Values("X-User-Id"); len(values) != 1 || values[0] != userID {
				t.Errorf("Core X-User-Id = %q, want only verified user", values)
			}
			values := got.header.Values("X-Request-Id")
			if len(values) != 1 || values[0] == "" || values[0] == clientID {
				t.Errorf("Core X-Request-Id = %q, want one new Gateway ID", values)
			}
			if got.header.Get("X-Custom") != customHeader || got.header.Get("Content-Type") != "application/json" {
				t.Errorf("ordinary request headers changed: X-Custom=%q, Content-Type=%q",
					got.header.Get("X-Custom"), got.header.Get("Content-Type"))
			}

			if resp.StatusCode != tc.wantStatus || string(body) != tc.wantBody {
				t.Errorf("Gateway response = (%d, %q), want (%d, %q)",
					resp.StatusCode, body, tc.wantStatus, tc.wantBody)
			}
			if resp.Header.Get("X-Core-Header") != "preserved" {
				t.Errorf("ordinary Core response header = %q", resp.Header.Get("X-Core-Header"))
			}
			if len(values) == 1 && resp.Header.Get("X-Request-Id") != values[0] {
				t.Errorf("client X-Request-Id = %q, Core request ID = %q",
					resp.Header.Get("X-Request-Id"), values[0])
			}
			if resp.Header.Get("X-Request-Id") == coreID {
				t.Error("Core replaced the Gateway request ID")
			}
			if previousID != "" && resp.Header.Get("X-Request-Id") == previousID {
				t.Error("Gateway reused a request ID")
			}
			previousID = resp.Header.Get("X-Request-Id")
			if got := resp.Header.Get("Access-Control-Allow-Origin"); got != tc.wantOrigin {
				t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, tc.wantOrigin)
			}
			if got := strings.Join(resp.Header.Values("Vary"), ","); !strings.Contains(got, "Origin") {
				t.Errorf("Vary = %q, want Origin", got)
			}
			credentials := resp.Header.Values("Access-Control-Allow-Credentials")
			if tc.wantOrigin != "" {
				if len(credentials) != 1 || credentials[0] != "true" {
					t.Errorf("Access-Control-Allow-Credentials = %q, want only Gateway true", credentials)
				}
			} else if len(credentials) != 0 {
				t.Errorf("Core credentials header leaked: %q", credentials)
			}
			if values := resp.Header.Values("Access-Control-Expose-Headers"); len(values) != 0 {
				t.Errorf("Core controlled client Access-Control-Expose-Headers: %q", values)
			}
		})
	}

	checkGatewayError := func(wantStatus int, bearer string) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+httpAddr+"/api/v1/requests", nil)
		if err != nil {
			t.Fatalf("create request: %v", err)
		}
		req.Header.Set("Origin", allowedOrigin)
		if bearer != "" {
			req.Header.Set("Authorization", bearer)
		}

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("call Gateway: %v", err)
		}
		defer closeTestBody(t, resp.Body)
		if resp.StatusCode != wantStatus {
			t.Errorf("Gateway status = %d, want %d", resp.StatusCode, wantStatus)
		}
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != allowedOrigin {
			t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, allowedOrigin)
		}
		if got := strings.Join(resp.Header.Values("Vary"), ","); !strings.Contains(got, "Origin") {
			t.Errorf("Vary = %q, want Origin", got)
		}
		if got := resp.Header.Get("Access-Control-Allow-Credentials"); got != "true" {
			t.Errorf("Access-Control-Allow-Credentials = %q, want true", got)
		}
		if got := resp.Header.Get("X-Request-Id"); got == "" {
			t.Error("Gateway error has no X-Request-Id")
		}
	}

	checkGatewayError(http.StatusUnauthorized, "")
	core.Close()
	checkGatewayError(http.StatusBadGateway, "Bearer "+token)
}

func unusedTCPAddress(t *testing.T) string {
	t.Helper()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

func waitForGatewayStart(t *testing.T, client *http.Client, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := getWithContext(t, client, "http://"+addr+"/healthz")
		if err == nil {
			if _, err := io.Copy(io.Discard, resp.Body); err != nil {
				t.Errorf("drain response body: %v", err)
			}
			if err := resp.Body.Close(); err != nil {
				t.Errorf("close response body: %v", err)
			}
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("Gateway did not start")
}
