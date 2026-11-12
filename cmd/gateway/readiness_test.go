package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"gitlab.com/team-anonyms/athelete-link/api-gateway/internal/config"
	"gitlab.com/team-anonyms/athelete-link/api-gateway/internal/httpapi"
)

func TestReadinessChecksRedisAndEveryService(t *testing.T) {
	tests := []struct {
		name       string
		redisError error
		failedPath string
		status     int
		wantStatus int
		wantCalls  [5]int32
	}{
		{name: "all healthy", wantStatus: http.StatusOK, wantCalls: [5]int32{1, 1, 1, 1, 1}},
		{name: "Redis unavailable", redisError: errors.New("unavailable"), wantStatus: http.StatusServiceUnavailable},
		{name: "Auth unavailable", failedPath: "/auth", status: http.StatusServiceUnavailable, wantStatus: http.StatusServiceUnavailable, wantCalls: [5]int32{1, 0, 0}},
		{name: "Core unavailable", failedPath: "/core", status: http.StatusInternalServerError, wantStatus: http.StatusServiceUnavailable, wantCalls: [5]int32{1, 1, 0}},
		{name: "Game unavailable", failedPath: "/game", status: http.StatusNotFound, wantStatus: http.StatusServiceUnavailable, wantCalls: [5]int32{1, 1, 1}},
		{name: "Profile unavailable", failedPath: "/profile", status: 503, wantStatus: 503, wantCalls: [5]int32{1, 1, 1, 1, 0}},
		{name: "Chat unavailable", failedPath: "/chat", status: 503, wantStatus: 503, wantCalls: [5]int32{1, 1, 1, 1, 1}},
		{name: "Auth redirect is not followed", failedPath: "/auth", status: http.StatusFound, wantStatus: http.StatusServiceUnavailable, wantCalls: [5]int32{1, 0, 0}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var calls [5]atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("health method = %s, want GET", r.Method)
				}
				if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
					t.Error("health request carried credentials")
				}
				switch r.URL.Path {
				case "/auth":
					calls[0].Add(1)
				case "/core":
					calls[1].Add(1)
				case "/game":
					calls[2].Add(1)
				case "/profile":
					calls[3].Add(1)
				case "/chat":
					calls[4].Add(1)
				default:
					t.Errorf("unexpected health path %q", r.URL.Path)
				}
				if r.URL.Path == tc.failedPath {
					if tc.status == http.StatusFound {
						w.Header().Set("Location", "/healthy")
					}
					w.WriteHeader(tc.status)
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			t.Cleanup(server.Close)

			cfg := config.Config{
				HealthTimeout:    time.Second,
				AuthHealthURL:    server.URL + "/auth",
				CoreHealthURL:    server.URL + "/core",
				GameHealthURL:    server.URL + "/game",
				ProfileHealthURL: server.URL + "/profile",
				ChatHealthURL:    server.URL + "/chat",
			}
			var redisCalls atomic.Int32
			checkRedis := func(ctx context.Context) error {
				redisCalls.Add(1)
				if _, ok := ctx.Deadline(); !ok {
					t.Error("Redis check has no shared deadline")
				}
				return tc.redisError
			}
			handler := readyTestHandler(newReadinessCheck(cfg, checkRedis))
			if got := redisCalls.Load(); got != 0 {
				t.Fatalf("readiness checked Redis before first request: %d calls", got)
			}

			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/readyz", nil))
			if response.Code != tc.wantStatus {
				t.Errorf("/readyz status = %d, want %d", response.Code, tc.wantStatus)
			}
			if got := redisCalls.Load(); got != 1 {
				t.Errorf("Redis calls = %d, want 1", got)
			}
			for i, want := range tc.wantCalls {
				if got := calls[i].Load(); got != want {
					t.Errorf("service %d calls = %d, want %d", i, got, want)
				}
			}
		})
	}
}

func TestReadinessRecoversWhenServiceRecovers(t *testing.T) {
	var status atomic.Int32
	status.Store(http.StatusServiceUnavailable)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(int(status.Load()))
	}))
	defer server.Close()

	cfg := config.Config{
		HealthTimeout:    time.Second,
		AuthHealthURL:    server.URL + "/auth",
		CoreHealthURL:    server.URL + "/core",
		GameHealthURL:    server.URL + "/game",
		ProfileHealthURL: server.URL + "/profile",
		ChatHealthURL:    server.URL + "/chat",
	}
	handler := readyTestHandler(newReadinessCheck(cfg, func(context.Context) error { return nil }))
	for _, tc := range []struct {
		upstreamStatus int32
		want           int
	}{
		{http.StatusServiceUnavailable, http.StatusServiceUnavailable},
		{http.StatusOK, http.StatusOK},
	} {
		status.Store(tc.upstreamStatus)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/readyz", nil))
		if response.Code != tc.want {
			t.Errorf("/readyz status = %d, want %d", response.Code, tc.want)
		}
	}
}

func TestReadinessRejectsHealthConnectionFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	failedURL := server.URL + "/auth"
	server.Close()

	cfg := config.Config{
		HealthTimeout:    time.Second,
		AuthHealthURL:    failedURL,
		CoreHealthURL:    failedURL,
		GameHealthURL:    failedURL,
		ProfileHealthURL: failedURL, ChatHealthURL: failedURL,
	}
	handler := readyTestHandler(newReadinessCheck(cfg, func(context.Context) error { return nil }))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/readyz", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Errorf("/readyz status = %d, want 503", response.Code)
	}
}

func TestReadinessUsesOneDeadlineForAllChecks(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(80 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := config.Config{
		HealthTimeout:    120 * time.Millisecond,
		AuthHealthURL:    server.URL + "/auth",
		CoreHealthURL:    server.URL + "/core",
		GameHealthURL:    server.URL + "/game",
		ProfileHealthURL: server.URL + "/profile",
		ChatHealthURL:    server.URL + "/chat",
	}
	handler := readyTestHandler(newReadinessCheck(cfg, func(context.Context) error { return nil }))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/readyz", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Errorf("/readyz status = %d, want 503", response.Code)
	}
}

func readyTestHandler(check func(context.Context) error) http.Handler {
	readiness := &httpapi.Readiness{}
	readiness.Set(true)
	return httpapi.NewHandler(httpapi.HandlerOptions{
		Readiness:       readiness,
		CheckDependency: check,
		NewRequestID:    func() string { return "ready-test-id" },
	})
}
