package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestGatewayStartsWithoutRedisButIsNotReady(t *testing.T) {
	addresses := unusedTCPAddresses(t, 2)
	httpAddr, redisAddr := addresses[0], addresses[1]
	t.Setenv("GATEWAY_HTTP_ADDR", httpAddr)
	setRequiredServiceURLsForTest(t, "http://127.0.0.1:1")
	t.Setenv("REDIS_ADDR", redisAddr)
	t.Setenv("JWT_SECRET", "test-only-secret")
	t.Setenv("GATEWAY_SHUTDOWN_TIMEOUT", "1s")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runWithContext(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("shutdown Gateway: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Gateway did not shut down")
		}
	})

	client := &http.Client{Timeout: 8 * time.Second}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := getWithContext(t, client, "http://"+httpAddr+"/healthz")
		if err == nil {
			if _, err := io.Copy(io.Discard, resp.Body); err != nil {
				t.Errorf("drain response body: %v", err)
			}
			if err := resp.Body.Close(); err != nil {
				t.Errorf("close response body: %v", err)
			}
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}

	assertHTTPStatus(t, client, "http://"+httpAddr+"/healthz", http.StatusOK)
	assertHTTPStatus(t, client, "http://"+httpAddr+"/readyz", http.StatusServiceUnavailable)
}

func setRequiredServiceURLsForTest(t *testing.T, coreURL string) {
	t.Helper()
	t.Setenv("GATEWAY_CORE_URL", coreURL)
	t.Setenv("GATEWAY_AUTH_URL", "http://127.0.0.1:1")
	t.Setenv("GATEWAY_GAME_URL", "http://127.0.0.1:1")
	t.Setenv("GATEWAY_PROFILE_URL", "http://127.0.0.1:1")
	t.Setenv("GATEWAY_CHAT_URL", "http://127.0.0.1:1")
	t.Setenv("GATEWAY_CORE_HEALTH_URL", "http://127.0.0.1:1/health")
	t.Setenv("GATEWAY_AUTH_HEALTH_URL", "http://127.0.0.1:1/health")
	t.Setenv("GATEWAY_GAME_HEALTH_URL", "http://127.0.0.1:1/health")
	t.Setenv("GATEWAY_PROFILE_HEALTH_URL", "http://127.0.0.1:1/health")
	t.Setenv("GATEWAY_CHAT_HEALTH_URL", "http://127.0.0.1:1/health")
	t.Setenv("GATEWAY_AUTH_TIMEOUT", "1s")
	t.Setenv("GATEWAY_GAME_TIMEOUT", "1s")
	t.Setenv("GATEWAY_PROFILE_TIMEOUT", "1s")
	t.Setenv("GATEWAY_CHAT_TIMEOUT", "1s")
}

func unusedTCPAddresses(t *testing.T, count int) []string {
	t.Helper()
	listeners := make([]net.Listener, 0, count)
	addresses := make([]string, 0, count)
	for range count {
		listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listeners = append(listeners, listener)
		addresses = append(addresses, listener.Addr().String())
	}
	for _, listener := range listeners {
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return addresses
}

func assertHTTPStatus(t *testing.T, client *http.Client, url string, want int) {
	t.Helper()
	resp, err := getWithContext(t, client, url)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestBody(t, resp.Body)
	if resp.StatusCode != want {
		t.Errorf("GET %s: status = %d, want %d", url, resp.StatusCode, want)
	}
}

func getWithContext(t *testing.T, client *http.Client, url string) (*http.Response, error) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return client.Do(request)
}

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
