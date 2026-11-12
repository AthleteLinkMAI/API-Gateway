package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestAuthAndGameProxyWiring(t *testing.T) {
	const (
		secret  = "gateway-service-wiring-test-key"
		userID  = "123e4567-e89b-42d3-a456-426614174001"
		tokenID = "123e4567-e89b-42d3-a456-426614174002"
	)

	type observedRequest struct {
		method string
		uri    string
		body   string
		header http.Header
	}
	authSeen := make(chan observedRequest, 1)
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read Auth request body: %v", err)
		}
		authSeen <- observedRequest{r.Method, r.URL.RequestURI(), string(body), r.Header.Clone()}
		w.Header().Set("Set-Cookie", "refreshToken=issued; HttpOnly")
		w.Header().Set("X-Request-Id", "auth-request-id")
		w.Header().Set("Access-Control-Allow-Origin", "https://auth.example")
		w.WriteHeader(http.StatusCreated)
		writeTestString(t, w, "auth-ok")
	}))
	t.Cleanup(auth.Close)

	gameSeen := make(chan observedRequest, 1)
	game := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gameSeen <- observedRequest{method: r.Method, uri: r.URL.RequestURI(), header: r.Header.Clone()}
		w.Header().Set("X-Request-Id", "game-request-id")
		w.WriteHeader(http.StatusAccepted)
		writeTestString(t, w, "game-ok")
	}))
	t.Cleanup(game.Close)

	addresses := unusedTCPAddresses(t, 2)
	httpAddr, redisAddr := addresses[0], addresses[1]
	t.Setenv("GATEWAY_HTTP_ADDR", httpAddr)
	setRequiredServiceURLsForTest(t, "http://127.0.0.1:1")
	t.Setenv("GATEWAY_AUTH_URL", auth.URL)
	t.Setenv("GATEWAY_GAME_URL", game.URL)
	t.Setenv("GATEWAY_CORE_TIMEOUT", "1s")
	t.Setenv("GATEWAY_WRITE_TIMEOUT", "3s")
	t.Setenv("GATEWAY_SHUTDOWN_TIMEOUT", "1s")
	t.Setenv("REDIS_ADDR", redisAddr)
	t.Setenv("JWT_SECRET", secret)

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
	waitForGatewayStart(t, client, httpAddr)
	baseURL := "http://" + httpAddr

	login, err := http.NewRequestWithContext(t.Context(), http.MethodPost, baseURL+"/api/v1/auth/login?source=web", strings.NewReader("credentials"))
	if err != nil {
		t.Fatal(err)
	}

	login.Header.Set("Cookie", "existing=value")
	login.Header.Set("X-Request-Id", "client-request-id")
	loginResponse, err := client.Do(login)
	if err != nil {
		t.Fatal(err)
	}
	loginBody, err := io.ReadAll(loginResponse.Body)
	if err := loginResponse.Body.Close(); err != nil {
		t.Errorf("close response body: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	if loginResponse.StatusCode != http.StatusCreated || string(loginBody) != "auth-ok" {
		t.Errorf("Auth response = (%d, %q), want (201, auth-ok)", loginResponse.StatusCode, loginBody)
	}
	if got := loginResponse.Header.Get("Set-Cookie"); got != "refreshToken=issued; HttpOnly" {
		t.Errorf("Auth Set-Cookie = %q", got)
	}
	if got := loginResponse.Header.Get("X-Request-Id"); got == "" || got == "client-request-id" || got == "auth-request-id" {
		t.Errorf("Auth X-Request-Id = %q, want Gateway ID", got)
	}
	if got := loginResponse.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Auth upstream CORS header leaked: %q", got)
	}
	gotAuth := <-authSeen
	if gotAuth.method != http.MethodPost || gotAuth.uri != "/api/v1/auth/login?source=web" || gotAuth.body != "credentials" {
		t.Errorf("Auth received (%s, %s, %q)", gotAuth.method, gotAuth.uri, gotAuth.body)
	}
	if gotAuth.header.Get("Authorization") != "" || gotAuth.header.Get("Cookie") != "existing=value" {
		t.Errorf("Auth received Authorization=%q, Cookie=%q", gotAuth.header.Get("Authorization"), gotAuth.header.Get("Cookie"))
	}

	now := time.Now()
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub": userID, "jti": tokenID, "type": "ACCESS",
		"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Hour).Unix(),
	}).SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	gameRequest, err := http.NewRequestWithContext(t.Context(), http.MethodGet, baseURL+"/api/v1/rank-tiers?limit=2", nil)
	if err != nil {
		t.Fatal(err)
	}
	gameRequest.Header.Set("Authorization", "Bearer "+token)
	gameRequest.Header.Set("Cookie", "refreshToken=client-cookie")
	gameRequest.Header.Set("X-User-Id", "forged-user")
	gameResponse, err := client.Do(gameRequest)
	if err != nil {
		t.Fatal(err)
	}
	gameBody, err := io.ReadAll(gameResponse.Body)
	if err := gameResponse.Body.Close(); err != nil {
		t.Errorf("close response body: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	if gameResponse.StatusCode != http.StatusAccepted || string(gameBody) != "game-ok" {
		t.Errorf("Game response = (%d, %q), want (202, game-ok)", gameResponse.StatusCode, gameBody)
	}
	if got := gameResponse.Header.Get("X-Request-Id"); got == "" || got == "game-request-id" {
		t.Errorf("Game X-Request-Id = %q, want Gateway ID", got)
	}
	gotGame := <-gameSeen
	if gotGame.method != http.MethodGet || gotGame.uri != "/api/v1/rank-tiers?limit=2" {
		t.Errorf("Game received (%s, %s)", gotGame.method, gotGame.uri)
	}
	if gotGame.header.Get("X-User-Id") != userID || gotGame.header.Get("Authorization") != "" || gotGame.header.Get("Cookie") != "" {
		t.Errorf("Game received X-User-Id=%q, Authorization=%q, Cookie=%q",
			gotGame.header.Get("X-User-Id"), gotGame.header.Get("Authorization"), gotGame.header.Get("Cookie"))
	}
}
