package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"gitlab.com/team-anonyms/athelete-link/api-gateway/internal/requestcontext"
)

func withRequestLogging(next http.Handler, logger *slog.Logger) http.Handler {
	if logger == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, diagnostics := requestcontext.WithDiagnostics(r.Context())
		r = r.WithContext(ctx)
		route, upstream, background := logOperationRoute(r.Method, r.URL.EscapedPath())
		response := &loggingResponseWriter{ResponseWriter: w}
		started := time.Now()
		completed := false

		defer func() {
			fields, status := completedRequestFields(ctx, diagnostics, response, completed)
			attrs := requestLogAttrs(r, route, upstream, fields, status, response.bytes, time.Since(started))
			level := requestLogLevel(status, fields, background || r.Method == http.MethodOptions)
			logger.LogAttrs(context.WithoutCancel(ctx), level, "http_request_completed", attrs...)
		}()

		next.ServeHTTP(response, r)
		completed = true
	})
}

func completedRequestFields(ctx context.Context, diagnostics *requestcontext.Diagnostics, response *loggingResponseWriter, completed bool) (requestcontext.DiagnosticFields, int) {
	fields := diagnostics.Snapshot()
	if !completed && fields.ErrorKind == "" {
		fields.ErrorKind = "handler_aborted"
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		fields.ErrorKind = "client_canceled"
	} else if errors.Is(ctx.Err(), context.DeadlineExceeded) && fields.ErrorKind == "" {
		fields.ErrorKind = "request_timeout"
	}
	status := response.status
	if status == 0 && completed && fields.ErrorKind == "" {
		status = http.StatusOK
	}
	if fields.ErrorKind == "" && response.writeFailed {
		fields.ErrorKind = "response_write_failed"
	}
	return fields, status
}

func requestLogAttrs(r *http.Request, route, upstream string, fields requestcontext.DiagnosticFields, status int, responseBytes int64, duration time.Duration) []slog.Attr {
	attrs := make([]slog.Attr, 0, 15)
	attrs = append(attrs,
		slog.String("request_id", fields.RequestID),
		slog.String("method", logMethod(r.Method)),
		slog.String("route", route),
		slog.String("upstream", upstream),
		slog.Bool("upstream_called", fields.UpstreamCalled),
		slog.Int("upstream_status", fields.UpstreamStatus),
		slog.Int("status", status),
		slog.Float64("duration_ms", float64(duration)/float64(time.Millisecond)),
		slog.Int64("response_bytes", responseBytes),
		slog.String("auth_result", fields.AuthResult),
		slog.String("denylist_result", fields.DenylistResult),
		slog.String("banlist_result", fields.BanlistResult),
	)
	if fields.UserID != "" {
		attrs = append(attrs, slog.String("user_id", fields.UserID))
	}
	if fields.ErrorKind != "" {
		attrs = append(attrs, slog.String("error_kind", fields.ErrorKind))
	}
	if fields.Dependency != "" {
		attrs = append(attrs, slog.String("dependency", fields.Dependency))
	}
	if route == "/api/v1/auth/logout" && r.Method == http.MethodDelete {
		cookie, err := r.Cookie("jwtRefreshToken")
		attrs = append(attrs, slog.Bool("logout_refresh_cookie_present", err == nil && cookie.Value != ""))
	}
	return attrs
}

func requestLogLevel(status int, fields requestcontext.DiagnosticFields, background bool) slog.Level {
	if fields.ErrorKind == "client_canceled" {
		return slog.LevelInfo
	}
	if status >= http.StatusInternalServerError || fields.DenylistResult == "error" || fields.BanlistResult == "error" ||
		fields.ErrorKind == "handler_aborted" || fields.ErrorKind == "response_write_failed" ||
		fields.ErrorKind == "upstream_body_failed" {
		return slog.LevelError
	}
	if status >= http.StatusBadRequest || fields.ErrorKind != "" || fields.DenylistResult == "unavailable" || fields.BanlistResult == "unavailable" {
		return slog.LevelWarn
	}
	if background {
		return slog.LevelDebug
	}
	return slog.LevelInfo
}

func logRoute(path string) (route, upstream string, background bool) {
	return logOperationRoute("", path)
}

func logOperationRoute(method, path string) (route, upstream string, background bool) {
	if match, ok := findAPIRoute(method, path); ok {
		service := "game"
		switch match.spec.upstream {
		case authUpstream:
			service = "auth"
		case coreUpstream:
			service = "core"
		case profileUpstream:
			service = "profile"
		case chatUpstream:
			service = "chat"
		}
		return match.spec.pattern, service, false
	}
	switch {
	case path == "/healthz", path == "/readyz", path == "/openapi.yaml", path == "/swagger":
		return path, "none", true
	case strings.HasPrefix(path, "/swagger/"):
		return "/swagger/*", "none", true
	default:
		return "unmatched", "none", false
	}
}

func logMethod(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete, http.MethodConnect, http.MethodOptions, http.MethodTrace:
		return method
	default:
		return "OTHER"
	}
}

type loggingResponseWriter struct {
	http.ResponseWriter
	status      int
	bytes       int64
	writeFailed bool
}

func (w *loggingResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *loggingResponseWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	if status >= http.StatusOK || status == http.StatusSwitchingProtocols {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *loggingResponseWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(body)
	w.bytes += int64(n)
	if err != nil {
		w.writeFailed = true
	}
	return n, err
}

func (w *loggingResponseWriter) FlushError() error {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	err := http.NewResponseController(w.ResponseWriter).Flush()
	if err != nil {
		w.writeFailed = true
	}
	return err
}
