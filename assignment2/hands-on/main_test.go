package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestProxyRequiresTokenAndForwardsAuthenticatedRequest(t *testing.T) {
	var receivedAuthorization string
	var receivedUser string
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		receivedAuthorization = request.Header.Get("Authorization")
		receivedUser = request.Header.Get("X-Authenticated-User")
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(upstreamURL)
	handler := newHandler(cfg)

	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/get", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without a token, got %d", unauthorized.Code)
	}

	tokenRequest := httptest.NewRequest(http.MethodPost, "/auth/token", nil)
	tokenRequest.SetBasicAuth(cfg.username, cfg.password)
	tokenRecorder := httptest.NewRecorder()
	handler.ServeHTTP(tokenRecorder, tokenRequest)
	if tokenRecorder.Code != http.StatusOK {
		t.Fatalf("expected token endpoint to return 200, got %d", tokenRecorder.Code)
	}

	var response tokenResponse
	if err := json.NewDecoder(tokenRecorder.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}

	proxyRequest := httptest.NewRequest(http.MethodGet, "/get", nil)
	proxyRequest.Header.Set("Authorization", "Bearer "+response.AccessToken)
	proxyRecorder := httptest.NewRecorder()
	handler.ServeHTTP(proxyRecorder, proxyRequest)

	if proxyRecorder.Code != http.StatusNoContent {
		t.Fatalf("expected upstream status 204, got %d", proxyRecorder.Code)
	}
	if receivedAuthorization != "" {
		t.Fatal("the proxy forwarded the JWT to the legacy service")
	}
	if receivedUser != cfg.username {
		t.Fatalf("expected authenticated user %q, got %q", cfg.username, receivedUser)
	}
}

func TestTokenEndpointRejectsInvalidCredentials(t *testing.T) {
	handler := newHandler(testConfig(&url.URL{Scheme: "http", Host: "legacy:8080"}))
	request := httptest.NewRequest(http.MethodPost, "/auth/token", nil)
	request.SetBasicAuth("wrong", "credentials")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", recorder.Code)
	}
}

func TestProxyRejectsTokenSignedWithDifferentSecret(t *testing.T) {
	cfg := testConfig(&url.URL{Scheme: "http", Host: "legacy:8080"})
	handler := newHandler(cfg)

	foreignCfg := cfg
	foreignCfg.jwtSecret = []byte(strings.Repeat("x", 32))
	tokenRequest := httptest.NewRequest(http.MethodPost, "/auth/token", nil)
	tokenRequest.SetBasicAuth(foreignCfg.username, foreignCfg.password)
	tokenRecorder := httptest.NewRecorder()
	newHandler(foreignCfg).ServeHTTP(tokenRecorder, tokenRequest)

	var response tokenResponse
	if err := json.NewDecoder(tokenRecorder.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "/get", nil)
	request.Header.Set("Authorization", "Bearer "+response.AccessToken)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a token signed with another secret, got %d", recorder.Code)
	}
}

func testConfig(upstream *url.URL) config {
	return config{
		listenAddr: ":8080",
		upstream:   upstream,
		jwtSecret:  []byte("0123456789abcdef0123456789abcdef"),
		username:   "student",
		password:   "correct-horse-battery-staple",
	}
}
