package auth

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"
	"gitlab.com/team-anonyms/athelete-link/api-gateway/internal/requestcontext"
)

var (
	ErrUserBanned       = errors.New("user banned")
	ErrInvalidToken     = errors.New("invalid access token")
	ErrCheckUnavailable = errors.New("access blocklist check unavailable")
	ErrRedisUnavailable = errors.New("redis unavailable or timed out")
)

var uuidPattern = regexp.MustCompile(
	`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`,
)

type Denylist interface {
	IsDenied(ctx context.Context, jti string) (bool, error)
	IsBanned(ctx context.Context, userID string) (bool, error)
}

type claims struct {
	Type string          `json:"type"`
	Role json.RawMessage `json:"role"`
	jwt.RegisteredClaims
}

type Verifier struct {
	key      []byte
	denylist Denylist
	clock    func() time.Time
}

func NewVerifier(
	secret string,
	denylist Denylist,
	clock func() time.Time,
) (*Verifier, error) {
	if denylist == nil || clock == nil {
		return nil, errors.New("incomplete verifier configuration")
	}
	if secret == "" {
		return nil, errors.New("JWT secret must not be empty")
	}
	if !utf8.ValidString(secret) {
		return nil, errors.New("JWT secret must be valid UTF-8")
	}

	return &Verifier{
		key:      []byte(secret),
		denylist: denylist,
		clock:    clock,
	}, nil
}

func (v *Verifier) VerifyAccessToken(
	ctx context.Context,
	raw string,
) (requestcontext.Identity, error) {
	var identity requestcontext.Identity
	requestcontext.UpdateDiagnostics(ctx, func(d *requestcontext.DiagnosticFields) {
		d.AuthResult = "rejected"
		d.ErrorKind = "invalid_token"
	})
	now := v.clock()

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodHS512.Alg()}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithTimeFunc(func() time.Time { return now }),
	)

	var c claims
	token, err := parser.ParseWithClaims(raw, &c, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != jwt.SigningMethodHS512.Alg() {
			return nil, ErrInvalidToken
		}

		return v.key, nil
	})
	if err != nil || !token.Valid {
		return identity, ErrInvalidToken
	}

	if c.Type != "ACCESS" ||
		!uuidPattern.MatchString(c.Subject) ||
		!uuidPattern.MatchString(c.ID) ||
		c.IssuedAt == nil ||
		c.ExpiresAt == nil {
		return identity, ErrInvalidToken
	}

	validIAT := !now.Before(c.IssuedAt.Time)
	validEXP := now.Before(c.ExpiresAt.Time)
	if !validIAT || !validEXP {
		return identity, ErrInvalidToken
	}

	denied, denyErr := v.denylist.IsDenied(ctx, c.ID)
	if ctx.Err() != nil {
		return identity, ctx.Err()
	}
	banned, banErr := v.denylist.IsBanned(ctx, c.Subject)
	if ctx.Err() != nil {
		requestcontext.UpdateDiagnostics(ctx, func(d *requestcontext.DiagnosticFields) { d.ErrorKind = "request_ended" })
		return identity, ctx.Err()
	}
	requestcontext.UpdateDiagnostics(ctx, func(d *requestcontext.DiagnosticFields) {
		d.DenylistResult = checkResult(denied, denyErr)
		d.BanlistResult = checkResult(banned, banErr)
	})
	if denied && denyErr == nil {
		requestcontext.UpdateDiagnostics(ctx, func(d *requestcontext.DiagnosticFields) { d.ErrorKind = "revoked_token" })
		return identity, ErrInvalidToken
	}
	if banned && banErr == nil {
		requestcontext.UpdateDiagnostics(ctx, func(d *requestcontext.DiagnosticFields) { d.ErrorKind = "user_banned" })
		return identity, ErrUserBanned
	}
	if denyErr != nil && !errors.Is(denyErr, ErrRedisUnavailable) || banErr != nil && !errors.Is(banErr, ErrRedisUnavailable) {
		requestcontext.UpdateDiagnostics(ctx, func(d *requestcontext.DiagnosticFields) {
			d.ErrorKind = "denylist_check_failed"
			if banErr != nil && !errors.Is(banErr, ErrRedisUnavailable) {
				d.ErrorKind = "banlist_check_failed"
			}
		})
		return identity, ErrCheckUnavailable
	}
	requestcontext.UpdateDiagnostics(ctx, func(d *requestcontext.DiagnosticFields) {
		d.AuthResult = "allowed"
		if denyErr != nil || banErr != nil {
			d.AuthResult = "allowed_without_denylist"
		}
		d.ErrorKind = ""
	})
	var role string
	_ = json.Unmarshal(c.Role, &role)
	if role != "ADMIN" && role != "MODERATOR" && role != "USER" {
		role = ""
	}
	return requestcontext.Identity{UserID: c.Subject, Role: role}, nil
}

func checkResult(found bool, err error) string {
	if errors.Is(err, ErrRedisUnavailable) {
		return "unavailable"
	}
	if err != nil {
		return "error"
	}
	if found {
		return "denied"
	}
	return "clear"
}
