package httpapi_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gitlab.com/team-anonyms/athelete-link/api-gateway/internal/httpapi"
	"gitlab.com/team-anonyms/athelete-link/api-gateway/internal/proxy"
	"gitlab.com/team-anonyms/athelete-link/api-gateway/internal/requestcontext"
)

func TestHealthEndpoint(t *testing.T) {
	t.Parallel()

	handler := newHealthHandler(
		&httpapi.Readiness{},
		func(context.Context) error { return errors.New("redis unavailable") },
	)
	recorder := serveRequest(handler, http.MethodGet, "/healthz")

	assertResponse(t, recorder, http.StatusOK, "ok\n")
	assertContentType(t, recorder)
}

func TestReadinessEndpointTracksState(t *testing.T) {
	t.Parallel()

	readiness := &httpapi.Readiness{}
	var dependencyErr error
	handler := newHealthHandler(readiness, func(context.Context) error {
		return dependencyErr
	})

	recorder := serveRequest(handler, http.MethodGet, "/readyz")
	assertResponse(t, recorder, http.StatusServiceUnavailable, "not ready\n")
	assertContentType(t, recorder)

	readiness.Set(true)
	recorder = serveRequest(handler, http.MethodGet, "/readyz")
	assertResponse(t, recorder, http.StatusOK, "ok\n")

	dependencyErr = errors.New("redis unavailable")
	recorder = serveRequest(handler, http.MethodGet, "/readyz")
	assertResponse(t, recorder, http.StatusServiceUnavailable, "not ready\n")

	dependencyErr = nil
	recorder = serveRequest(handler, http.MethodGet, "/readyz")
	assertResponse(t, recorder, http.StatusOK, "ok\n")

	readiness.Set(false)
	recorder = serveRequest(handler, http.MethodGet, "/readyz")
	assertResponse(t, recorder, http.StatusServiceUnavailable, "not ready\n")
}

func TestHealthEndpointRejectsUnsupportedMethod(t *testing.T) {
	t.Parallel()

	handler := newHealthHandler(&httpapi.Readiness{}, healthyDependency)
	recorder := serveRequest(handler, http.MethodPost, "/healthz")

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandlerReturnsNotFoundForUnregisteredPaths(t *testing.T) {
	t.Parallel()

	handler := newHealthHandler(&httpapi.Readiness{}, healthyDependency)
	paths := []string{"/", "/unknown", "/healthz/", "/readyz/"}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			recorder := serveRequest(handler, http.MethodGet, path)
			if recorder.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNotFound)
			}
		})
	}
}

func TestHandlerRoutesOnlyCorePathsWithoutChangingRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		method     string
		target     string
		wantStatus int
		wantCore   bool
	}{
		{"requests root", http.MethodPost, "/api/v1/requests?x=1", http.StatusAccepted, true},
		{"requests child", http.MethodPut, "/api/v1/requests/123", http.StatusAccepted, true},
		{"requests subtree", http.MethodDelete, "/api/v1/requests/123/participants/456", http.StatusNotFound, false},
		{"requests trailing slash", http.MethodGet, "/api/v1/requests/", http.StatusNotFound, false},
		{"repeated slash", http.MethodGet, "/api/v1/requests//123?x=1", http.StatusNotFound, false},
		{"dot segment", http.MethodGet, "/api/v1/requests/./123", http.StatusNotFound, false},
		{"sports", http.MethodGet, "/api/v1/sports", http.StatusAccepted, true},
		{"old requests root", http.MethodGet, "/requests", http.StatusNotFound, false},
		{"old requests child", http.MethodGet, "/requests/123", http.StatusNotFound, false},
		{"old sports", http.MethodGet, "/sports", http.StatusNotFound, false},
		{"wrong child method", http.MethodPatch, "/api/v1/requests/123", http.StatusMethodNotAllowed, false},
		{"escaped parameter slash", http.MethodGet, "/api/v1/requests/a%2Fb", http.StatusNotFound, false},
		{"requests lookalike", http.MethodGet, "/api/v1/requests-extra", http.StatusNotFound, false},
		{"escaped slash", http.MethodGet, "/api/v1/requests%2F123", http.StatusNotFound, false},
		{"sports child", http.MethodGet, "/api/v1/sports/123", http.StatusNotFound, false},
		{"sports trailing slash", http.MethodGet, "/api/v1/sports/", http.StatusNotFound, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			calls := 0
			var gotMethod, gotURI string
			core := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				gotMethod = r.Method
				gotURI = r.URL.RequestURI()
				w.WriteHeader(http.StatusAccepted)
			})
			handler := httpapi.NewHandler(httpapi.HandlerOptions{
				Readiness:       &httpapi.Readiness{},
				CheckDependency: healthyDependency,
				CoreProxy:       core,
				CoreTimeout:     time.Second,
				WriteTimeout:    2 * time.Second,
				Verifier:        allowRoutingVerifier{},
				NewRequestID:    func() string { return "test-request-id" },
			})
			request := httptest.NewRequestWithContext(t.Context(), tc.method, tc.target, nil)
			if tc.wantCore {
				request.Header.Set("Authorization", "Bearer test-token")
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)

			if recorder.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", recorder.Code, tc.wantStatus)
			}
			if tc.wantCore {
				if calls != 1 {
					t.Fatalf("Core calls = %d, want 1", calls)
				}
				if gotMethod != tc.method || gotURI != tc.target {
					t.Errorf("Core received %s %s, want %s %s", gotMethod, gotURI, tc.method, tc.target)
				}
			} else if calls != 0 {
				t.Errorf("Core calls = %d, want 0", calls)
			}
		})
	}
}

func TestCorePreflightRunsBeforeAuthentication(t *testing.T) {
	t.Parallel()

	const allowedOrigin = "https://app.example"
	tests := []struct {
		name            string
		path            string
		origin          string
		requestedMethod string
		wantStatus      int
		wantOrigin      string
	}{
		{
			name:            "allowed preflight",
			path:            "/api/v1/requests",
			origin:          allowedOrigin,
			requestedMethod: http.MethodPost,
			wantStatus:      http.StatusNoContent,
			wantOrigin:      allowedOrigin,
		},
		{
			name:            "foreign origin",
			path:            "/api/v1/sports",
			origin:          "https://foreign.example",
			requestedMethod: http.MethodGet,
			wantStatus:      http.StatusForbidden,
		},
		{
			name:       "ordinary options is not declared",
			path:       "/api/v1/requests",
			origin:     allowedOrigin,
			wantStatus: http.StatusMethodNotAllowed,
			wantOrigin: allowedOrigin,
		},
		{
			name:            "unknown path is not a Core preflight",
			path:            "/unknown",
			origin:          allowedOrigin,
			requestedMethod: http.MethodPost,
			wantStatus:      http.StatusNotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			verifier := &countingVerifier{}
			coreCalls := 0
			core := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				coreCalls++
				w.WriteHeader(http.StatusAccepted)
			})
			handler := httpapi.NewHandler(httpapi.HandlerOptions{
				Readiness:       &httpapi.Readiness{},
				CheckDependency: healthyDependency,
				CoreProxy:       core,
				CoreTimeout:     time.Second,
				WriteTimeout:    2 * time.Second,
				Verifier:        verifier,
				NewRequestID:    func() string { return "gateway-request-id" },
				CORSOrigins:     []string{allowedOrigin},
			})

			request := httptest.NewRequestWithContext(t.Context(), http.MethodOptions, tc.path, nil)
			request.Header.Set("Origin", tc.origin)
			request.Header.Set("X-Request-Id", "client-request-id")
			if tc.requestedMethod != "" {
				request.Header.Set("Access-Control-Request-Method", tc.requestedMethod)
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)

			if recorder.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", recorder.Code, tc.wantStatus)
			}
			if got := recorder.Header().Get("X-Request-Id"); got != "gateway-request-id" {
				t.Errorf("X-Request-Id = %q, want gateway-request-id", got)
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
			if tc.path != "/unknown" {
				vary := strings.Join(recorder.Header().Values("Vary"), ",")
				wantVary := []string{"Origin"}
				if tc.requestedMethod != "" {
					wantVary = append(wantVary, "Access-Control-Request-Method", "Access-Control-Request-Headers")
				}
				for _, name := range wantVary {
					if !strings.Contains(vary, name) {
						t.Errorf("Vary = %q, want %s", vary, name)
					}
				}
			}
			if tc.wantOrigin != "" && tc.requestedMethod != "" {
				if got := recorder.Header().Get("Access-Control-Allow-Methods"); got != tc.requestedMethod {
					t.Errorf("Access-Control-Allow-Methods = %q, want %q", got, tc.requestedMethod)
				}
				if got := recorder.Header().Get("Access-Control-Allow-Headers"); !strings.Contains(got, "Authorization") {
					t.Errorf("Access-Control-Allow-Headers = %q, want Authorization", got)
				}
			}
			if verifier.calls != 0 || coreCalls != 0 {
				t.Errorf("verifier calls = %d, Core calls = %d; want both zero", verifier.calls, coreCalls)
			}
		})
	}
}

func TestCoreCORSOnOrdinaryResponses(t *testing.T) {
	t.Parallel()

	const allowedOrigin = "https://app.example"
	tests := []struct {
		name         string
		origin       string
		token        bool
		coreStatus   int
		gatewayError bool
		wantStatus   int
		wantOrigin   string
		wantCore     bool
	}{
		{"Core success", allowedOrigin, true, http.StatusOK, false, http.StatusOK, allowedOrigin, true},
		{"Core business error", allowedOrigin, true, http.StatusConflict, false, http.StatusConflict, allowedOrigin, true},
		{"Gateway authentication error", allowedOrigin, false, 0, false, http.StatusUnauthorized, allowedOrigin, false},
		{"Gateway upstream error", allowedOrigin, true, 0, true, http.StatusBadGateway, allowedOrigin, true},
		{"foreign origin", "https://foreign.example", true, http.StatusOK, false, http.StatusOK, "", true},
		{"no origin", "", true, http.StatusOK, false, http.StatusOK, "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			coreCalls := 0
			core := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				coreCalls++
				if tc.gatewayError {
					proxy.HandleUpstreamError(w, r, errors.New("upstream unavailable"))
					return
				}
				w.WriteHeader(tc.coreStatus)
			})
			handler := httpapi.NewHandler(httpapi.HandlerOptions{
				Readiness:       &httpapi.Readiness{},
				CheckDependency: healthyDependency,
				CoreProxy:       core,
				CoreTimeout:     time.Second,
				WriteTimeout:    2 * time.Second,
				Verifier:        allowRoutingVerifier{},
				NewRequestID:    func() string { return "gateway-request-id" },
				CORSOrigins:     []string{allowedOrigin},
			})
			request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/requests", nil)
			if tc.origin != "" {
				request.Header.Set("Origin", tc.origin)
			}
			if tc.token {
				request.Header.Set("Authorization", "Bearer test-token")
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)

			if recorder.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", recorder.Code, tc.wantStatus)
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
			if got := recorder.Header().Get("X-Request-Id"); got != "gateway-request-id" {
				t.Errorf("X-Request-Id = %q, want gateway-request-id", got)
			}
			if (coreCalls == 1) != tc.wantCore {
				t.Errorf("Core calls = %d, wantCore = %t", coreCalls, tc.wantCore)
			}
		})
	}
}

func TestOrdinaryOptionsWithJWTIsRejectedBeforeCore(t *testing.T) {
	t.Parallel()

	verifier := &countingVerifier{}
	coreCalls := 0
	core := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		coreCalls++
		w.WriteHeader(http.StatusAccepted)
	})
	handler := httpapi.NewHandler(httpapi.HandlerOptions{
		Readiness:       &httpapi.Readiness{},
		CheckDependency: healthyDependency,
		CoreProxy:       core,
		CoreTimeout:     time.Second,
		WriteTimeout:    2 * time.Second,
		Verifier:        verifier,
		NewRequestID:    func() string { return "gateway-request-id" },
		CORSOrigins:     []string{"https://app.example"},
	})
	request := httptest.NewRequestWithContext(t.Context(), http.MethodOptions, "/api/v1/requests", nil)
	request.Header.Set("Origin", "https://app.example")
	request.Header.Set("Authorization", "Bearer test-token")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusMethodNotAllowed || verifier.calls != 0 || coreCalls != 0 || recorder.Header().Get("Allow") != "GET, POST" {
		t.Errorf("status = %d, verifier calls = %d, Core calls = %d; want 405, 0, 0",
			recorder.Code, verifier.calls, coreCalls)
	}
}

type allowRoutingVerifier struct{}

func (allowRoutingVerifier) VerifyAccessToken(context.Context, string) (requestcontext.Identity, error) {
	return requestcontext.Identity{UserID: "verified-user"}, nil
}

type countingVerifier struct {
	calls int
}

func (v *countingVerifier) VerifyAccessToken(context.Context, string) (requestcontext.Identity, error) {
	v.calls++
	return requestcontext.Identity{UserID: "verified-user"}, nil
}

func serveRequest(handler http.Handler, method, path string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(
		context.Background(),
		method,
		path,
		nil,
	)
	handler.ServeHTTP(recorder, request)

	return recorder
}

func healthyDependency(context.Context) error { return nil }

func newHealthHandler(
	readiness *httpapi.Readiness,
	checkDependency func(context.Context) error,
) http.Handler {
	return httpapi.NewHandler(httpapi.HandlerOptions{
		Readiness:       readiness,
		CheckDependency: checkDependency,
		CoreProxy:       http.NotFoundHandler(),
		CoreTimeout:     time.Second,
		WriteTimeout:    2 * time.Second,
		NewRequestID:    func() string { return "test-request-id" },
	})
}

func assertResponse(
	t *testing.T,
	recorder *httptest.ResponseRecorder,
	wantStatus int,
	wantBody string,
) {
	t.Helper()

	if recorder.Code != wantStatus {
		t.Errorf("status = %d, want %d", recorder.Code, wantStatus)
	}

	if recorder.Body.String() != wantBody {
		t.Errorf("body = %q, want %q", recorder.Body.String(), wantBody)
	}
}

func assertContentType(t *testing.T, recorder *httptest.ResponseRecorder) {
	t.Helper()

	const want = "text/plain; charset=utf-8"
	if got := recorder.Header().Get("Content-Type"); got != want {
		t.Errorf("Content-Type = %q, want %q", got, want)
	}
}
