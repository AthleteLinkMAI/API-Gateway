package auth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"

	"github.com/redis/go-redis/v9"
)

type existsClient interface {
	Exists(ctx context.Context, keys ...string) *redis.IntCmd
}

type RedisDenylist struct {
	client existsClient
}

func NewRedisDenylist(client existsClient) *RedisDenylist {
	return &RedisDenylist{client: client}
}

func (r *RedisDenylist) IsDenied(
	ctx context.Context,
	jti string,
) (bool, error) {
	return r.exists(ctx, "jwt:denylist:"+jti)
}

func (r *RedisDenylist) IsBanned(ctx context.Context, userID string) (bool, error) {
	return r.exists(ctx, "user:banlist:"+userID)
}

func (r *RedisDenylist) exists(ctx context.Context, key string) (bool, error) {
	count, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		if ctx.Err() != nil {
			return false, err
		}
		if isRedisUnavailable(err) {
			return false, fmt.Errorf("%w: %w", ErrRedisUnavailable, err)
		}
		return false, err
	}

	return count != 0, nil
}

func isRedisUnavailable(err error) bool {
	var commandErr redis.Error
	if errors.As(err, &commandErr) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, redis.ErrPoolTimeout) ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.ECONNABORTED) ||
		errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ETIMEDOUT)
}
