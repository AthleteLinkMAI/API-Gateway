package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"gitlab.com/team-anonyms/athelete-link/api-gateway/internal/httpapi"
	"gitlab.com/team-anonyms/athelete-link/api-gateway/internal/proxy"
	"gitlab.com/team-anonyms/athelete-link/api-gateway/internal/requestcontext"
)

type immediateAccessVerifier struct{}

func (immediateAccessVerifier) VerifyAccessToken(context.Context, string) (requestcontext.Identity, error) {
	return requestcontext.Identity{UserID: "123e4567-e89b-42d3-a456-426614174001"}, nil
}

type delayedAccessVerifier struct{ delay time.Duration }

func (v delayedAccessVerifier) VerifyAccessToken(ctx context.Context, _ string) (requestcontext.Identity, error) {
	timer := time.NewTimer(v.delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return requestcontext.Identity{UserID: "123e4567-e89b-42d3-a456-426614174001"}, nil
	case <-ctx.Done():
		return requestcontext.Identity{}, ctx.Err()
	}
}

func newCoreProxyHandler(t *testing.T, coreURL string, timeout, writeTimeout time.Duration, verifier httpapi.AccessVerifier) http.Handler {
	t.Helper()
	target, err := url.Parse(coreURL)
	if err != nil {
		t.Fatalf("parse Core URL: %v", err)
	}
	reverseProxy, err := proxy.NewReverseProxy(target, proxy.RewriteCore, proxy.HandleUpstreamError)
	if err != nil {
		t.Fatalf("create Core proxy: %v", err)
	}
	return httpapi.NewHandler(httpapi.HandlerOptions{
		Readiness:       &httpapi.Readiness{},
		CheckDependency: func(context.Context) error { return nil },
		CoreProxy:       reverseProxy,
		CoreTimeout:     timeout,
		WriteTimeout:    writeTimeout,
		Verifier:        verifier,
		NewRequestID:    func() string { return "gateway-request-id" },
	})
}

func TestCoreClientCancellationThroughHTTPHandler(t *testing.T) {
	coreStarted := make(chan struct{})
	coreCanceled := make(chan error, 1)
	core := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(coreStarted)
		<-r.Context().Done()
		coreCanceled <- r.Context().Err()
	}))
	defer core.Close()

	gateway := httptest.NewServer(newCoreProxyHandler(t, core.URL, 5*time.Second, 10*time.Second, immediateAccessVerifier{}))
	defer gateway.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, gateway.URL+"/api/v1/requests", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	request.Header.Set("Authorization", "Bearer test-token")

	clientResult := make(chan error, 1)
	go func() {
		response, err := gateway.Client().Do(request)
		if response != nil {
			if err := response.Body.Close(); err != nil {
				t.Errorf("close response body: %v", err)
			}
		}
		clientResult <- err
	}()

	select {
	case <-coreStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("request did not reach Core")
	}
	cancel()

	select {
	case err := <-clientResult:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("client error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("client request did not stop after cancellation")
	}
	select {
	case err := <-coreCanceled:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Core context error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Core request was not canceled")
	}
}

func TestCoreTimeoutAfterResponseHeadersAbortsBody(t *testing.T) {
	coreCanceled := make(chan struct{}, 1)
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		writeTestString(t, w, "first chunk")
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Errorf("flush response: %v", err)
		}
		<-r.Context().Done()
		coreCanceled <- struct{}{}
	}))
	defer core.Close()

	gateway := httptest.NewServer(newCoreProxyHandler(t, core.URL, 250*time.Millisecond, time.Second, immediateAccessVerifier{}))
	defer gateway.Close()
	client := &http.Client{Timeout: 8 * time.Second}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, gateway.URL+"/api/v1/requests", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	request.Header.Set("Authorization", "Bearer test-token")

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("call Gateway: %v", err)
	}
	body, readErr := io.ReadAll(response.Body)
	if err := response.Body.Close(); err != nil {
		t.Errorf("close response body: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want Core's already-sent 200", response.StatusCode)
	}
	if !strings.HasPrefix(string(body), "first chunk") {
		t.Errorf("body = %q, want first Core chunk", body)
	}
	if readErr == nil {
		t.Error("body read completed cleanly after Core timeout")
	}
	select {
	case <-coreCanceled:
	case <-time.After(2 * time.Second):
		t.Error("Core request was not canceled after body timeout")
	}
}

func TestCoreTimeoutRemainsWritableAfterAuthentication(t *testing.T) {
	for _, tc := range []struct {
		name      string
		authDelay time.Duration
	}{
		{name: "authentication shorter than initial write timeout", authDelay: 350 * time.Millisecond},
		{name: "authentication longer than initial write timeout", authDelay: 450 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			core := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				<-r.Context().Done()
			}))
			defer core.Close()

			handler := newCoreProxyHandler(t, core.URL, 200*time.Millisecond, 400*time.Millisecond, delayedAccessVerifier{delay: tc.authDelay})
			gateway := httptest.NewUnstartedServer(handler)
			gateway.Config.WriteTimeout = 400 * time.Millisecond
			gateway.Start()
			defer gateway.Close()

			client := &http.Client{Timeout: 8 * time.Second}
			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, gateway.URL+"/api/v1/requests", nil)
			if err != nil {
				t.Fatalf("create request: %v", err)
			}
			request.Header.Set("Authorization", "Bearer test-token")
			response, err := client.Do(request)
			if err != nil {
				t.Fatalf("call Gateway: expected HTTP 504 after Core timeout, got %v", err)
			}
			defer closeTestBody(t, response.Body)
			if response.StatusCode != http.StatusGatewayTimeout {
				t.Errorf("status = %d, want 504 after Core timeout", response.StatusCode)
			}
		})
	}
}
