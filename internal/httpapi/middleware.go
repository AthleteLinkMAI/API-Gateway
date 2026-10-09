package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"gitlab.com/team-anonyms/athelete-link/api-gateway/internal/auth"
	"gitlab.com/team-anonyms/athelete-link/api-gateway/internal/requestcontext"
)

type Middleware func(http.Handler) http.Handler

type AccessVerifier interface {
	VerifyAccessToken(context.Context, string) (requestcontext.Identity, error)
}

func Chain(next http.Handler, middleware ...Middleware) http.Handler {
	for i := len(middleware) - 1; i >= 0; i-- {
		next = middleware[i](next)
	}

	return next
}

func withUpstreamTimeout(next http.Handler, timeout, writeTimeout time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := setWriteDeadline(w, time.Now().Add(writeTimeout)); err != nil {
			recordFailure(r.Context(), "write_deadline_failed")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func withRequestID(next http.Handler, newID func() string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := newID()
		if id == "" {
			recordFailure(r.Context(), "request_id_failed")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("X-Request-Id", id)
		requestcontext.UpdateDiagnostics(r.Context(), func(d *requestcontext.DiagnosticFields) {
			d.RequestID = id
		})
		ctx := requestcontext.WithRequestID(r.Context(), id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func withAccessAuth(next http.Handler, verifier AccessVerifier, writeTimeout time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestcontext.UpdateDiagnostics(r.Context(), func(d *requestcontext.DiagnosticFields) {
			d.AuthResult = "rejected"
		})
		if _, ok := requestcontext.RequestIDFrom(r.Context()); !ok {
			recordFailure(r.Context(), "request_id_missing")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		token, ok := bearerToken(r.Header.Values("Authorization"))
		if !ok {
			recordFailure(r.Context(), "missing_bearer")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if err := setWriteDeadline(w, time.Time{}); err != nil {
			recordFailure(r.Context(), "write_deadline_failed")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		identity, err := verifier.VerifyAccessToken(r.Context(), token)
		if r.Context().Err() != nil {
			return
		}
		if deadlineErr := setWriteDeadline(w, time.Now().Add(writeTimeout)); deadlineErr != nil {
			recordFailure(r.Context(), "write_deadline_failed")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		if err != nil {
			recordAccessError(r.Context(), err)
			writeAccessError(w, err)
			return
		}
		if identity.UserID == "" {
			recordFailure(r.Context(), "verified_identity_missing")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		recordVerifiedIdentity(r.Context(), identity)
		ctx := requestcontext.WithIdentity(r.Context(), identity)
		ctx = requestcontext.WithVerifiedAccessToken(ctx, token)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func recordAccessError(ctx context.Context, err error) {
	requestcontext.UpdateDiagnostics(ctx, func(d *requestcontext.DiagnosticFields) {
		if d.ErrorKind != "" {
			return
		}
		d.ErrorKind = "invalid_token"
		if errors.Is(err, auth.ErrCheckUnavailable) {
			d.ErrorKind = "denylist_check_failed"
		}
	})
}

func recordVerifiedIdentity(ctx context.Context, identity requestcontext.Identity) {
	requestcontext.UpdateDiagnostics(ctx, func(d *requestcontext.DiagnosticFields) {
		d.UserID = identity.UserID
		if d.AuthResult != "allowed_without_denylist" {
			d.AuthResult = "allowed"
		}
	})
}

func writeAccessError(w http.ResponseWriter, err error) {
	status := http.StatusUnauthorized
	if errors.Is(err, auth.ErrCheckUnavailable) {
		status = http.StatusServiceUnavailable
	}
	http.Error(w, http.StatusText(status), status)
}

func bearerToken(values []string) (string, bool) {
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return "", false
	}
	token := strings.TrimPrefix(values[0], "Bearer ")
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return "", false
	}
	return token, true
}

func withOwnUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		match, matched := findAPIRoute(r.Method, r.URL.EscapedPath())
		identity, verified := requestcontext.IdentityFrom(r.Context())
		if !matched || match.spec.access != ownUserAccess || !verified {
			recordFailure(r.Context(), "own_user_check_failed")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		if !strings.EqualFold(match.userID, identity.UserID) {
			recordFailure(r.Context(), "own_user_mismatch")
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func withCurrentUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		match, matched := findAPIRoute(r.Method, r.URL.EscapedPath())
		identity, verified := requestcontext.IdentityFrom(r.Context())
		if !matched || match.spec.access != currentUserAccess || !verified {
			recordFailure(r.Context(), "current_user_check_failed")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		out := r.Clone(r.Context())
		out.URL.Path = match.spec.pattern + "/" + identity.UserID
		out.URL.RawPath = ""
		next.ServeHTTP(w, out)
	})
}

func setWriteDeadline(w http.ResponseWriter, deadline time.Time) error {
	err := http.NewResponseController(w).SetWriteDeadline(deadline)
	if errors.Is(err, http.ErrNotSupported) {
		return nil
	}
	return err
}

func recordFailure(ctx context.Context, kind string) {
	requestcontext.UpdateDiagnostics(ctx, func(d *requestcontext.DiagnosticFields) {
		d.ErrorKind = kind
	})
}

func withAPIPreflight(next http.Handler, origins []string) http.Handler {
	allowed := make(map[string]struct{}, len(origins))
	for _, origin := range origins {
		allowed[origin] = struct{}{}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		method := r.Header.Get("Access-Control-Request-Method")
		w.Header().Add("Vary", "Origin")

		_, originAllowed := allowed[origin]
		originAllowed = originAllowed || isLocalhostOrigin(origin)
		if originAllowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		if r.Method != http.MethodOptions || origin == "" || method == "" {
			next.ServeHTTP(w, r)
			return
		}

		w.Header().Add("Vary", "Access-Control-Request-Method")
		w.Header().Add("Vary", "Access-Control-Request-Headers")
		if _, matched := findAPIRoute(method, r.URL.EscapedPath()); !matched {
			recordFailure(r.Context(), "method_not_allowed")
			w.Header().Set("Allow", allowedMethods(r.URL.EscapedPath()))
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}

		if !originAllowed {
			recordFailure(r.Context(), "cors_origin_denied")
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		w.Header().Set("Access-Control-Allow-Methods", method)
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.WriteHeader(http.StatusNoContent)
	})
}

func isLocalhostOrigin(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || !isHTTPOriginURL(u) ||
		!strings.EqualFold(u.Hostname(), "localhost") || u.String() != origin {
		return false
	}

	port := u.Port()
	if port == "" {
		return strings.EqualFold(u.Host, "localhost")
	}
	value, err := strconv.Atoi(port)
	return err == nil && value >= 1 && value <= 65535 &&
		strings.EqualFold(u.Host, "localhost:"+port)
}

func isHTTPOriginURL(u *url.URL) bool {
	return (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" &&
		u.User == nil && u.Opaque == "" && u.Path == "" && u.RawPath == "" &&
		u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.RawFragment == ""
}
