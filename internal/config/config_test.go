package config_test

import (
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"gitlab.com/team-anonyms/athelete-link/api-gateway/internal/config"
)

type environment map[string]string

var requiredURLs = environment{
	"GATEWAY_CORE_URL":           "http://core.example",
	"GATEWAY_AUTH_URL":           "http://auth.example",
	"GATEWAY_GAME_URL":           "http://game.example",
	"GATEWAY_PROFILE_URL":        "http://profile.example",
	"GATEWAY_CHAT_URL":           "http://chat.example",
	"GATEWAY_CORE_HEALTH_URL":    "http://core.example/health",
	"GATEWAY_AUTH_HEALTH_URL":    "http://auth.example/health",
	"GATEWAY_GAME_HEALTH_URL":    "http://game.example/health",
	"GATEWAY_PROFILE_HEALTH_URL": "http://profile.example/health",
	"GATEWAY_CHAT_HEALTH_URL":    "http://chat.example/health",
}

func (env environment) lookup(key string) (string, bool) {
	value, ok := env[key]

	return value, ok
}

func withRequiredURLs(overrides environment) environment {
	env := make(environment, len(requiredURLs)+len(overrides))
	for key, value := range requiredURLs {
		env[key] = value
	}
	for key, value := range overrides {
		env[key] = value
	}
	return env
}

func TestLoadDefaults(t *testing.T) {
	t.Parallel()

	got, err := config.Load(withRequiredURLs(nil).lookup)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	want := config.Config{
		HTTPAddr:          ":8080",
		CoreURL:           requiredURLs["GATEWAY_CORE_URL"],
		AuthURL:           requiredURLs["GATEWAY_AUTH_URL"],
		GameURL:           requiredURLs["GATEWAY_GAME_URL"],
		ChatURL:           requiredURLs["GATEWAY_CHAT_URL"],
		ProfileURL:        requiredURLs["GATEWAY_PROFILE_URL"],
		CoreTimeout:       10 * time.Second,
		AuthTimeout:       10 * time.Second,
		GameTimeout:       10 * time.Second,
		ChatTimeout:       10 * time.Second,
		ProfileTimeout:    10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		ShutdownTimeout:   10 * time.Second,
		HealthTimeout:     2 * time.Second,
		LogLevel:          slog.LevelInfo,
		RedisAddr:         "localhost:6379",
		CoreHealthURL:     requiredURLs["GATEWAY_CORE_HEALTH_URL"],
		AuthHealthURL:     requiredURLs["GATEWAY_AUTH_HEALTH_URL"],
		GameHealthURL:     requiredURLs["GATEWAY_GAME_HEALTH_URL"],
		ChatHealthURL:     requiredURLs["GATEWAY_CHAT_HEALTH_URL"],
		ProfileHealthURL:  requiredURLs["GATEWAY_PROFILE_HEALTH_URL"],
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Load() = %#v, want %#v", got, want)
	}
}

func TestLoadOverrides(t *testing.T) {
	t.Parallel()

	env := environment{
		"GATEWAY_HTTP_ADDR":           "127.0.0.1:9090",
		"GATEWAY_CORE_URL":            "https://core.example/",
		"GATEWAY_AUTH_URL":            "https://auth.example/",
		"GATEWAY_GAME_URL":            "https://game.example/",
		"GATEWAY_CHAT_URL":            "https://chat.example/",
		"GATEWAY_PROFILE_URL":         "https://profile.example/",
		"GATEWAY_CORE_HEALTH_URL":     "https://core.example/actuator/health?full=true",
		"GATEWAY_AUTH_HEALTH_URL":     "https://auth.example/health",
		"GATEWAY_GAME_HEALTH_URL":     "https://game.example/health",
		"GATEWAY_CHAT_HEALTH_URL":     "https://chat.example/health",
		"GATEWAY_PROFILE_HEALTH_URL":  "https://profile.example/health",
		"GATEWAY_CORS_ORIGINS":        "https://app.example, http://localhost:3000",
		"GATEWAY_CORE_TIMEOUT":        "2s",
		"GATEWAY_AUTH_TIMEOUT":        "1s",
		"GATEWAY_GAME_TIMEOUT":        "1500ms",
		"GATEWAY_CHAT_TIMEOUT":        "1500ms",
		"GATEWAY_PROFILE_TIMEOUT":     "1500ms",
		"GATEWAY_HEALTH_TIMEOUT":      "500ms",
		"GATEWAY_READ_HEADER_TIMEOUT": "1s",
		"GATEWAY_READ_TIMEOUT":        "2s",
		"GATEWAY_WRITE_TIMEOUT":       "3s",
		"GATEWAY_IDLE_TIMEOUT":        "4s",
		"GATEWAY_SHUTDOWN_TIMEOUT":    "5s",
		"GATEWAY_LOG_LEVEL":           "debug",
		"REDIS_ADDR":                  "127.0.0.1:6380",
		"REDIS_PASSWORD":              "test-only-redis-password",
		"JWT_SECRET":                  "test-only-secret-not-for-production",
	}

	got, err := config.Load(env.lookup)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	want := config.Config{
		HTTPAddr:          "127.0.0.1:9090",
		CoreURL:           "https://core.example/",
		AuthURL:           "https://auth.example/",
		GameURL:           "https://game.example/",
		ChatURL:           "https://chat.example/",
		ProfileURL:        "https://profile.example/",
		CoreHealthURL:     "https://core.example/actuator/health?full=true",
		AuthHealthURL:     "https://auth.example/health",
		GameHealthURL:     "https://game.example/health",
		ChatHealthURL:     "https://chat.example/health",
		ProfileHealthURL:  "https://profile.example/health",
		CORSOrigins:       []string{"https://app.example", "http://localhost:3000"},
		CoreTimeout:       2 * time.Second,
		AuthTimeout:       time.Second,
		GameTimeout:       1500 * time.Millisecond,
		ChatTimeout:       1500 * time.Millisecond,
		ProfileTimeout:    1500 * time.Millisecond,
		HealthTimeout:     500 * time.Millisecond,
		ReadHeaderTimeout: time.Second,
		ReadTimeout:       2 * time.Second,
		WriteTimeout:      3 * time.Second,
		IdleTimeout:       4 * time.Second,
		ShutdownTimeout:   5 * time.Second,
		LogLevel:          slog.LevelDebug,
		RedisAddr:         "127.0.0.1:6380",
		RedisPassword:     "test-only-redis-password",
		JWTSecret:         "test-only-secret-not-for-production",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Load() = %#v, want %#v", got, want)
	}
}

func TestLoadRejectsUnknownLogLevel(t *testing.T) {
	t.Parallel()

	assertLoadError(
		t,
		environment{"GATEWAY_LOG_LEVEL": "verbose"},
		"GATEWAY_LOG_LEVEL",
	)
}

func TestLoadRejectsMalformedDuration(t *testing.T) {
	t.Parallel()

	assertLoadError(
		t,
		environment{"GATEWAY_READ_TIMEOUT": "later"},
		"GATEWAY_READ_TIMEOUT",
	)
}

func TestLoadRejectsZeroDuration(t *testing.T) {
	t.Parallel()

	assertLoadError(
		t,
		environment{"GATEWAY_WRITE_TIMEOUT": "0s"},
		"GATEWAY_WRITE_TIMEOUT",
	)
}

func TestLoadRejectsNegativeDuration(t *testing.T) {
	t.Parallel()

	assertLoadError(
		t,
		environment{"GATEWAY_IDLE_TIMEOUT": "-1s"},
		"GATEWAY_IDLE_TIMEOUT",
	)
}

func TestLoadRejectsEmptyAddress(t *testing.T) {
	t.Parallel()

	for _, key := range []string{"GATEWAY_HTTP_ADDR"} {
		t.Run(key, func(t *testing.T) {
			t.Parallel()
			assertLoadError(t, environment{key: " \t"}, key)
		})
	}
}

func TestLoadRejectsInvalidCORSOrigins(t *testing.T) {
	t.Parallel()

	for _, value := range []string{
		"", " ", "*", "app.example", "ftp://app.example",
		"https://app.example/", "https://app.example/path",
		"https://app.example?key=value", "https://app.example#fragment",
		"https://user:pass@app.example", "https://app.example,",
		"https://app.example, https://app.example",
	} {
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			assertLoadError(t, environment{"GATEWAY_CORS_ORIGINS": value}, "GATEWAY_CORS_ORIGINS")
		})
	}
}

func TestLoadRejectsInvalidUpstreamAndHealthTimeouts(t *testing.T) {
	t.Parallel()

	for _, key := range []string{
		"GATEWAY_CORE_TIMEOUT", "GATEWAY_AUTH_TIMEOUT",
		"GATEWAY_PROFILE_TIMEOUT", "GATEWAY_CHAT_TIMEOUT", "GATEWAY_GAME_TIMEOUT", "GATEWAY_HEALTH_TIMEOUT",
	} {
		t.Run(key, func(t *testing.T) {
			t.Parallel()
			for _, value := range []string{"later", "0s", "-1s", "15s", "16s"} {
				t.Run(value, func(t *testing.T) {
					t.Parallel()
					assertLoadError(t, environment{key: value}, key)
				})
			}
		})
	}
}

func TestLoadComparesUpstreamAndHealthTimeoutsWithWriteTimeout(t *testing.T) {
	t.Parallel()

	for _, key := range []string{
		"GATEWAY_CORE_TIMEOUT", "GATEWAY_AUTH_TIMEOUT",
		"GATEWAY_PROFILE_TIMEOUT", "GATEWAY_CHAT_TIMEOUT", "GATEWAY_GAME_TIMEOUT", "GATEWAY_HEALTH_TIMEOUT",
	} {
		t.Run(key, func(t *testing.T) {
			t.Parallel()
			assertLoadError(t, environment{key: "15s"}, key)
		})
	}
	assertLoadError(t, environment{"GATEWAY_WRITE_TIMEOUT": "3s"}, "GATEWAY_CORE_TIMEOUT")

	cfg, err := config.Load(withRequiredURLs(environment{
		"GATEWAY_CORE_TIMEOUT":    "2s",
		"GATEWAY_AUTH_TIMEOUT":    "2s",
		"GATEWAY_GAME_TIMEOUT":    "2s",
		"GATEWAY_CHAT_TIMEOUT":    "2s",
		"GATEWAY_PROFILE_TIMEOUT": "2s",
		"GATEWAY_WRITE_TIMEOUT":   "3s",
	}).lookup)
	if err != nil {
		t.Fatalf("Load() with Core timeout below write timeout: %v", err)
	}
	if cfg.CoreTimeout != 2*time.Second || cfg.WriteTimeout != 3*time.Second {
		t.Fatalf("Load() timeouts = (%s, %s), want (2s, 3s)", cfg.CoreTimeout, cfg.WriteTimeout)
	}
}

func TestLoadRejectsEmptyRedisPassword(t *testing.T) {
	t.Parallel()
	assertLoadError(t, environment{"REDIS_PASSWORD": " \t"}, "REDIS_PASSWORD")
}

func TestLoadRejectsMissingRequiredURLs(t *testing.T) {
	t.Parallel()

	for key := range requiredURLs {
		t.Run(key, func(t *testing.T) {
			t.Parallel()
			env := withRequiredURLs(nil)
			delete(env, key)
			_, err := config.Load(env.lookup)
			if err == nil || !strings.Contains(err.Error(), key) {
				t.Fatalf("Load() error = %v, want missing %s", err, key)
			}
		})
	}
}

func TestLoadRejectsInvalidUpstreamURLs(t *testing.T) {
	t.Parallel()

	for _, key := range []string{
		"GATEWAY_CORE_URL", "GATEWAY_AUTH_URL", "GATEWAY_PROFILE_URL", "GATEWAY_CHAT_URL", "GATEWAY_GAME_URL",
	} {
		t.Run(key, func(t *testing.T) {
			t.Parallel()
			for _, value := range []string{
				"", "core:8081", "ftp://core.example", "http://",
				"http://user:pass@core.example", "http://core.example/path",
				"http://core.example?key=value", "http://core.example#fragment",
				"http://core.example?", "http://core.example#",
				" http://core.example ",
			} {
				t.Run(value, func(t *testing.T) {
					t.Parallel()
					assertLoadError(t, environment{key: value}, key)
				})
			}
		})
	}
}

func TestLoadRejectsInvalidHealthURLs(t *testing.T) {
	t.Parallel()

	for _, key := range []string{
		"GATEWAY_CORE_HEALTH_URL", "GATEWAY_AUTH_HEALTH_URL", "GATEWAY_PROFILE_HEALTH_URL", "GATEWAY_CHAT_HEALTH_URL", "GATEWAY_GAME_HEALTH_URL",
	} {
		t.Run(key, func(t *testing.T) {
			t.Parallel()
			for _, value := range []string{
				"", "health", "ftp://core.example/health", "http://",
				"http://user:pass@core.example/health",
				"http://core.example/health#fragment", "http://core.example/health#",
				" http://core.example/health ",
			} {
				t.Run(value, func(t *testing.T) {
					t.Parallel()
					assertLoadError(t, environment{key: value}, key)
				})
			}
		})
	}
}

func assertLoadError(t *testing.T, env environment, wantSubstring string) {
	t.Helper()

	_, err := config.Load(withRequiredURLs(env).lookup)
	if err == nil {
		t.Fatal("Load() error = nil, want non-nil error")
	}

	if !strings.Contains(err.Error(), wantSubstring) {
		t.Fatalf("Load() error = %q, want substring %q", err, wantSubstring)
	}
}
