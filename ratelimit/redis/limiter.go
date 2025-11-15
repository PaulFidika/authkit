package redislimiter

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Limit defines window and max count for a bucket.
type Limit struct {
	Limit  int
	Window time.Duration
}

// Limiter is a Redis-backed sliding window limiter using ZSETs.
type Limiter struct {
	rdb    *redis.Client
	ctx    context.Context
	limits map[string]Limit
}

func New(rdb *redis.Client, limits map[string]Limit) *Limiter {
	if limits == nil {
		limits = map[string]Limit{}
	}
	return &Limiter{rdb: rdb, ctx: context.Background(), limits: limits}
}

func (l *Limiter) get(bucket string) (Limit, bool) {
	if v, ok := l.limits[bucket]; ok {
		return v, true
	}
	if v, ok := l.limits["default"]; ok {
		return v, true
	}
	return Limit{Limit: 100, Window: time.Minute}, false
}

// AllowNamed matches the auth adapter's internal interface.
func (l *Limiter) AllowNamed(bucket, key string) (bool, error) {
	if l == nil || l.rdb == nil {
		return true, nil
	}
	if bucket == "" || key == "" {
		return false, fmt.Errorf("bucket and key required")
	}
	lim, _ := l.get(bucket)
	now := time.Now().UnixNano() / 1e6 // ms
	start := now - lim.Window.Milliseconds()
	limitKey := fmt.Sprintf("%s:%s", key, bucket)
	pipe := l.rdb.TxPipeline()
	pipe.ZAdd(l.ctx, limitKey, redis.Z{Score: float64(now), Member: now})
	pipe.ZRemRangeByScore(l.ctx, limitKey, "0", fmt.Sprintf("%d", start))
	countCmd := pipe.ZCard(l.ctx, limitKey)
	pipe.Expire(l.ctx, limitKey, lim.Window+time.Second)
	if _, err := pipe.Exec(l.ctx); err != nil {
		return false, err
	}
	count, err := countCmd.Result()
	if err != nil {
		return false, err
	}
	if count > int64(lim.Limit) {
		l.rdb.ZRem(l.ctx, limitKey, now)
		return false, nil
	}
	return true, nil
}
