package httpapi_test

import (
	"net/http"
	"strings"
	"testing"

	"gitlab.com/team-anonyms/athelete-link/api-gateway/internal/httpapi"
)

func TestDocumentationEndpointsServeEmbeddedAssets(t *testing.T) {
	t.Parallel()

	handler := newHealthHandler(&httpapi.Readiness{}, healthyDependency)
	tests := []struct {
		path        string
		contentType string
		contains    string
	}{
		{"/openapi.yaml", "application/yaml; charset=utf-8", "openapi: 3.1.0"},
		{"/swagger/", "text/html; charset=utf-8", "swagger-ui-bundle.js"},
		{"/swagger/swagger-initializer.js", "text/javascript; charset=utf-8", "url: \"/openapi.yaml\""},
		{"/swagger/swagger-ui-bundle.js", "text/javascript; charset=utf-8", "SwaggerUIBundle"},
		{"/swagger/swagger-ui.css", "text/css; charset=utf-8", ".swagger-ui"},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()
			response := serveRequest(handler, http.MethodGet, tc.path)
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", response.Code)
			}
			if got := response.Header().Get("Content-Type"); got != tc.contentType {
				t.Errorf("Content-Type = %q, want %q", got, tc.contentType)
			}
			if got := response.Header().Get("X-Request-Id"); got != "test-request-id" {
				t.Errorf("X-Request-Id = %q, want test-request-id", got)
			}
			if !strings.Contains(response.Body.String(), tc.contains) {
				t.Errorf("response body does not contain %q", tc.contains)
			}
		})
	}
}

func TestDocumentationRoutesHaveExplicitBoundaries(t *testing.T) {
	t.Parallel()

	handler := newHealthHandler(&httpapi.Readiness{}, healthyDependency)
	redirect := serveRequest(handler, http.MethodGet, "/swagger")
	if redirect.Code != http.StatusMovedPermanently || redirect.Header().Get("Location") != "/swagger/" {
		t.Errorf("/swagger redirect = %d %q", redirect.Code, redirect.Header().Get("Location"))
	}

	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodPost, "/openapi.yaml", http.StatusMethodNotAllowed},
		{http.MethodPost, "/swagger/", http.StatusMethodNotAllowed},
		{http.MethodGet, "/swagger/missing.js", http.StatusNotFound},
		{http.MethodGet, "/openapi.yaml/", http.StatusNotFound},
	} {
		response := serveRequest(handler, tc.method, tc.path)
		if response.Code != tc.want {
			t.Errorf("%s %s status = %d, want %d", tc.method, tc.path, response.Code, tc.want)
		}
	}
}

func TestDocumentationIncludesCurrentServiceOperations(t *testing.T) {
	t.Parallel()
	handler := newHealthHandler(&httpapi.Readiness{}, healthyDependency)
	response := serveRequest(handler, http.MethodGet, "/openapi.yaml")
	contract := response.Body.String()
	if !strings.Contains(contract, "  \"/api/v1/user/me\":\n") || strings.Contains(contract, "  \"/api/v1/user/me/{userId}\":\n") {
		t.Error("embedded contract must expose only the ID-less me route")
	}
	for _, operation := range []string{
		"me", "getUsersByUserIds", "getCurrentPlayerSummary", "getCurrentPlayerSummaryTrailingSlash",
	} {
		if !strings.Contains(response.Body.String(), "operationId: "+operation) {
			t.Errorf("embedded contract lacks %s", operation)
		}
	}
	if !strings.Contains(contract, "  \"/api/v1/user\":\n") ||
		!strings.Contains(contract, "#/components/schemas/Auth_UserPublicControllerDto") {
		t.Error("embedded contract lacks the user lookup route or public user response schema")
	}
	for _, path := range []string{
		"/api/v1/requests/users/{userId}",
		"/api/v1/players/{userId}/other-sports",
		"/api/v1/players/{userId}/last-game",
		"/api/v1/players/{userId}/best-sport",
		"/api/v1/players/{userId}/matches/{page}/{cntPerPage}",
		"/api/v1/leaderboards/{sportId}/{page}/{cntPerPage}",
	} {
		if !strings.Contains(contract, "  \""+path+"\":\n") {
			t.Errorf("embedded contract lacks %s", path)
		}
	}
	if strings.Contains(contract, "  \"/api/v1/requests/{requestId}/rounds\":\n") {
		t.Error("embedded contract still exposes the removed round list route")
	}
	for _, path := range []string{
		"/api/v1/players/{userId}/matches",
		"/api/v1/leaderboards/{sportId}",
	} {
		if strings.Contains(contract, "  \""+path+"\":\n") {
			t.Errorf("embedded contract still exposes %s", path)
		}
	}
}
