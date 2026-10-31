package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	issuer        = "jwt-auth-proxy"
	audience      = "legacy-service"
	tokenLifetime = 15 * time.Minute
)

type config struct {
	listenAddr string
	upstream   *url.URL
	jwtSecret  []byte
	username   string
	password   string
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}

	server := &http.Server{
		Addr:              cfg.listenAddr,
		Handler:           newHandler(cfg),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("JWT proxy listening on %s and forwarding to %s", cfg.listenAddr, cfg.upstream)
	log.Fatal(server.ListenAndServe())
}

func loadConfig() (config, error) {
	upstream, err := url.Parse(envOrDefault("UPSTREAM_URL", "http://legacy:8080"))
	if err != nil || upstream.Scheme == "" || upstream.Host == "" {
		return config{}, errors.New("UPSTREAM_URL must be an absolute HTTP(S) URL")
	}

	secret := os.Getenv("JWT_SECRET")
	if len(secret) < 32 {
		return config{}, errors.New("JWT_SECRET must contain at least 32 characters")
	}

	username := os.Getenv("AUTH_USERNAME")
	password := os.Getenv("AUTH_PASSWORD")
	if username == "" || password == "" {
		return config{}, errors.New("AUTH_USERNAME and AUTH_PASSWORD must be set")
	}

	return config{
		listenAddr: envOrDefault("LISTEN_ADDR", ":8080"),
		upstream:   upstream,
		jwtSecret:  []byte(secret),
		username:   username,
		password:   password,
	}, nil
}

func newHandler(cfg config) http.Handler {
	proxy := httputil.NewSingleHostReverseProxy(cfg.upstream)
	originalDirector := proxy.Director
	proxy.Director = func(request *http.Request) {
		originalHost := request.Host
		originalDirector(request)
		request.Header.Del("Authorization")
		request.Header.Set("X-Forwarded-Host", originalHost)
	}
	proxy.ErrorHandler = func(writer http.ResponseWriter, _ *http.Request, err error) {
		log.Printf("upstream error: %v", err)
		writeJSON(writer, http.StatusBadGateway, errorResponse{Error: "upstream service is unavailable"})
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/token", tokenHandler(cfg))
	mux.HandleFunc("/auth/token", methodNotAllowed(http.MethodPost))
	mux.HandleFunc("GET /healthz", func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.Handle("/", authenticate(cfg, proxy))
	return securityHeaders(mux)
}

func tokenHandler(cfg config) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		username, password, ok := request.BasicAuth()
		usernameOK := subtle.ConstantTimeCompare([]byte(username), []byte(cfg.username)) == 1
		passwordOK := subtle.ConstantTimeCompare([]byte(password), []byte(cfg.password)) == 1
		if !ok || !usernameOK || !passwordOK {
			writer.Header().Set("WWW-Authenticate", `Basic realm="token"`)
			writeJSON(writer, http.StatusUnauthorized, errorResponse{Error: "invalid credentials"})
			return
		}

		now := time.Now()
		claims := jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   username,
			Audience:  jwt.ClaimStrings{audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(tokenLifetime)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		signedToken, err := token.SignedString(cfg.jwtSecret)
		if err != nil {
			writeJSON(writer, http.StatusInternalServerError, errorResponse{Error: "could not create token"})
			return
		}

		writeJSON(writer, http.StatusOK, tokenResponse{
			AccessToken: signedToken,
			TokenType:   "Bearer",
			ExpiresIn:   int64(tokenLifetime.Seconds()),
		})
	}
}

func authenticate(cfg config, next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		header := request.Header.Get("Authorization")
		parts := strings.Fields(header)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			writer.Header().Set("WWW-Authenticate", "Bearer")
			writeJSON(writer, http.StatusUnauthorized, errorResponse{Error: "a Bearer token is required"})
			return
		}

		claims := &jwt.RegisteredClaims{}
		token, err := jwt.ParseWithClaims(
			parts[1],
			claims,
			func(token *jwt.Token) (any, error) {
				if token.Method != jwt.SigningMethodHS256 {
					return nil, fmt.Errorf("unexpected signing method: %s", token.Method.Alg())
				}
				return cfg.jwtSecret, nil
			},
			jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
			jwt.WithIssuer(issuer),
			jwt.WithAudience(audience),
			jwt.WithExpirationRequired(),
		)
		if err != nil || !token.Valid || claims.Subject == "" {
			writer.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			writeJSON(writer, http.StatusUnauthorized, errorResponse{Error: "token is invalid or expired"})
			return
		}

		request.Header.Set("X-Authenticated-User", claims.Subject)
		next.ServeHTTP(writer, request)
	})
}

func methodNotAllowed(allowed string) http.HandlerFunc {
	return func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Allow", allowed)
		writeJSON(writer, http.StatusMethodNotAllowed, errorResponse{Error: "method not allowed"})
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(writer, request)
	})
}

func writeJSON(writer http.ResponseWriter, status int, body any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	if err := json.NewEncoder(writer).Encode(body); err != nil {
		log.Printf("could not encode response: %v", err)
	}
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
