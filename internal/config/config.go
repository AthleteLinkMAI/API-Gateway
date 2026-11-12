package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"
)

type LookupFunc func(string) (string, bool)

type Config struct {
	HTTPAddr          string
	CoreURL           string
	AuthURL           string
	GameURL           string
	ProfileURL        string
	ChatURL           string
	CORSOrigins       []string
	CoreTimeout       time.Duration
	AuthTimeout       time.Duration
	GameTimeout       time.Duration
	ProfileTimeout    time.Duration
	ChatTimeout       time.Duration
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration
	HealthTimeout     time.Duration
	LogLevel          slog.Level
	RedisAddr         string
	RedisPassword     string
	JWTSecret         string
	AuthHealthURL     string
	CoreHealthURL     string
	GameHealthURL     string
	ProfileHealthURL  string
	ChatHealthURL     string
}

var defaultConfig = Config{
	HTTPAddr:          ":8080",
	CoreTimeout:       10 * time.Second,
	AuthTimeout:       10 * time.Second,
	GameTimeout:       10 * time.Second,
	ProfileTimeout:    10 * time.Second,
	ChatTimeout:       10 * time.Second,
	ReadHeaderTimeout: 5 * time.Second,
	ReadTimeout:       15 * time.Second,
	WriteTimeout:      15 * time.Second,
	IdleTimeout:       60 * time.Second,
	ShutdownTimeout:   10 * time.Second,
	HealthTimeout:     2 * time.Second,
	LogLevel:          slog.LevelInfo,
	RedisAddr:         "localhost:6379",
}

func Load(lookup LookupFunc) (Config, error) {
	cfg := defaultConfig

	if err := overrideNonEmpty(
		lookup, "GATEWAY_HTTP_ADDR", &cfg.HTTPAddr,
	); err != nil {
		return Config{}, err
	}

	if err := loadServiceURLs(lookup, &cfg); err != nil {
		return Config{}, err
	}

	var err error
	if raw, ok := lookup("GATEWAY_CORS_ORIGINS"); ok {
		cfg.CORSOrigins, err = parseCORSOrigins(raw)
		if err != nil {
			return Config{}, fmt.Errorf("GATEWAY_CORS_ORIGINS: %w", err)
		}
	}

	if err := loadDurations(lookup, &cfg); err != nil {
		return Config{}, err
	}

	cfg.LogLevel, err = logLevel(lookup, "GATEWAY_LOG_LEVEL", cfg.LogLevel)
	if err != nil {
		return Config{}, err
	}

	for _, entry := range []struct {
		key    string
		target *string
	}{
		{"REDIS_ADDR", &cfg.RedisAddr},
		{"REDIS_PASSWORD", &cfg.RedisPassword},
		{"JWT_SECRET", &cfg.JWTSecret},
	} {
		if err := overrideNonEmpty(lookup, entry.key, entry.target); err != nil {
			return Config{}, err
		}
	}

	return cfg, nil
}

func loadServiceURLs(lookup LookupFunc, cfg *Config) error {
	for _, entry := range []struct {
		key    string
		target *string
		health bool
	}{
		{"GATEWAY_CORE_URL", &cfg.CoreURL, false},
		{"GATEWAY_AUTH_URL", &cfg.AuthURL, false},
		{"GATEWAY_GAME_URL", &cfg.GameURL, false},
		{"GATEWAY_PROFILE_URL", &cfg.ProfileURL, false},
		{"GATEWAY_CHAT_URL", &cfg.ChatURL, false},
		{"GATEWAY_CORE_HEALTH_URL", &cfg.CoreHealthURL, true},
		{"GATEWAY_AUTH_HEALTH_URL", &cfg.AuthHealthURL, true},
		{"GATEWAY_GAME_HEALTH_URL", &cfg.GameHealthURL, true},
		{"GATEWAY_PROFILE_HEALTH_URL", &cfg.ProfileHealthURL, true},
		{"GATEWAY_CHAT_HEALTH_URL", &cfg.ChatHealthURL, true},
	} {
		value, ok := lookup(entry.key)
		if !ok {
			return fmt.Errorf("%s: is required", entry.key)
		}
		var err error
		if entry.health {
			err = validateHealthURL(value)
		} else {
			err = validateUpstreamURL(value)
		}
		if err != nil {
			return fmt.Errorf("%s: %w", entry.key, err)
		}
		*entry.target = value
	}
	return nil
}

func loadDurations(lookup LookupFunc, cfg *Config) error {
	var err error

	cfg.CoreTimeout, err = positiveDuration(
		lookup, "GATEWAY_CORE_TIMEOUT", cfg.CoreTimeout,
	)
	if err != nil {
		return err
	}
	cfg.AuthTimeout, err = positiveDuration(
		lookup, "GATEWAY_AUTH_TIMEOUT", cfg.AuthTimeout,
	)
	if err != nil {
		return err
	}
	cfg.GameTimeout, err = positiveDuration(
		lookup, "GATEWAY_GAME_TIMEOUT", cfg.GameTimeout,
	)
	if err != nil {
		return err
	}
	cfg.ProfileTimeout, err = positiveDuration(lookup, "GATEWAY_PROFILE_TIMEOUT", cfg.ProfileTimeout)
	if err != nil {
		return err
	}
	cfg.ChatTimeout, err = positiveDuration(lookup, "GATEWAY_CHAT_TIMEOUT", cfg.ChatTimeout)
	if err != nil {
		return err
	}
	cfg.HealthTimeout, err = positiveDuration(
		lookup, "GATEWAY_HEALTH_TIMEOUT", cfg.HealthTimeout,
	)
	if err != nil {
		return err
	}

	cfg.ReadHeaderTimeout, err = positiveDuration(
		lookup, "GATEWAY_READ_HEADER_TIMEOUT", cfg.ReadHeaderTimeout,
	)
	if err != nil {
		return err
	}

	cfg.ReadTimeout, err = positiveDuration(
		lookup, "GATEWAY_READ_TIMEOUT", cfg.ReadTimeout,
	)
	if err != nil {
		return err
	}

	cfg.WriteTimeout, err = positiveDuration(
		lookup, "GATEWAY_WRITE_TIMEOUT", cfg.WriteTimeout,
	)
	if err != nil {
		return err
	}

	for _, timeout := range []struct {
		key   string
		value time.Duration
	}{
		{"GATEWAY_CORE_TIMEOUT", cfg.CoreTimeout},
		{"GATEWAY_AUTH_TIMEOUT", cfg.AuthTimeout},
		{"GATEWAY_GAME_TIMEOUT", cfg.GameTimeout},
		{"GATEWAY_PROFILE_TIMEOUT", cfg.ProfileTimeout},
		{"GATEWAY_CHAT_TIMEOUT", cfg.ChatTimeout},
		{"GATEWAY_HEALTH_TIMEOUT", cfg.HealthTimeout},
	} {
		if timeout.value >= cfg.WriteTimeout {
			return fmt.Errorf("%s must be less than GATEWAY_WRITE_TIMEOUT", timeout.key)
		}
	}

	cfg.IdleTimeout, err = positiveDuration(
		lookup, "GATEWAY_IDLE_TIMEOUT", cfg.IdleTimeout,
	)
	if err != nil {
		return err
	}

	cfg.ShutdownTimeout, err = positiveDuration(
		lookup, "GATEWAY_SHUTDOWN_TIMEOUT", cfg.ShutdownTimeout,
	)
	if err != nil {
		return err
	}

	return nil
}

func overrideNonEmpty(lookup LookupFunc, key string, target *string) error {
	value, ok := lookup(key)
	if !ok {
		return nil
	}
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s: must not be empty", key)
	}
	*target = value
	return nil
}

func validateUpstreamURL(value string) error {
	if value == "" || strings.TrimSpace(value) != value ||
		strings.ContainsAny(value, "?#") {
		return errors.New("must be an HTTP(S) URL with a host")
	}

	parsed, err := url.Parse(value)
	if err != nil || parsed == nil || !validURLAuthority(parsed) || !validUpstreamURLPath(parsed) {
		return errors.New("must be an HTTP(S) URL with a host and no credentials, path, query, or fragment")
	}

	return nil
}

func validateHealthURL(value string) error {
	if value == "" || strings.TrimSpace(value) != value || strings.Contains(value, "#") {
		return errors.New("must be an HTTP(S) URL with a host and no credentials or fragment")
	}

	parsed, err := url.Parse(value)
	if err != nil || parsed == nil || !validURLAuthority(parsed) {
		return errors.New("must be an HTTP(S) URL with a host and no credentials or fragment")
	}
	return nil
}

func validURLAuthority(parsed *url.URL) bool {
	return (parsed.Scheme == "http" || parsed.Scheme == "https") &&
		parsed.Hostname() != "" && parsed.User == nil && parsed.Opaque == ""
}

func validUpstreamURLPath(parsed *url.URL) bool {
	return (parsed.Path == "" || parsed.Path == "/") &&
		parsed.RawPath == "" && parsed.RawQuery == "" && !parsed.ForceQuery &&
		parsed.Fragment == "" && parsed.RawFragment == ""
}

func positiveDuration(
	lookup LookupFunc,
	key string,
	fallback time.Duration,
) (time.Duration, error) {
	value, ok := lookup(key)
	if !ok {
		return fallback, nil
	}

	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf(
			"%s: invalid duration: %q: %w",
			key, value, err,
		)
	}

	if duration <= 0 {
		return 0, fmt.Errorf(
			"%s: must be positive, got %q",
			key, value,
		)
	}

	return duration, nil

}

func logLevel(
	lookup LookupFunc,
	key string,
	fallback slog.Level,
) (slog.Level, error) {
	val, ok := lookup(key)
	if !ok {
		return fallback, nil
	}

	switch strings.ToLower(val) {
	case "debug":
		return slog.LevelDebug, nil

	case "info":
		return slog.LevelInfo, nil

	case "warn":
		return slog.LevelWarn, nil

	case "error":
		return slog.LevelError, nil

	default:
		return 0, fmt.Errorf(
			"%s: allowed values: debug, info, warn, error, got %q",
			key, val,
		)
	}
}

func parseCORSOrigins(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("must not be empty")
	}

	origins := make([]string, 0)
	seen := make(map[string]struct{})

	for _, part := range strings.Split(raw, ",") {
		origin := strings.TrimSpace(part)
		if !validCORSOrigin(origin) {
			return nil, fmt.Errorf("invalid origin %q", origin)
		}

		if _, exists := seen[origin]; exists {
			return nil, fmt.Errorf("duplicate origin %q", origin)
		}

		seen[origin] = struct{}{}
		origins = append(origins, origin)
	}

	return origins, nil
}

func validCORSOrigin(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || u == nil {
		return false
	}
	return (u.Scheme == "http" || u.Scheme == "https") &&
		u.Hostname() != "" && u.User == nil && u.Opaque == "" &&
		u.Path == "" && u.RawPath == "" &&
		u.RawQuery == "" && !u.ForceQuery &&
		u.Fragment == "" && u.RawFragment == "" &&
		u.String() == origin
}
