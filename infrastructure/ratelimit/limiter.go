package ratelimit

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// Decision es el resultado de evaluar un request contra una regla.
type Decision struct {
	Allowed    bool
	Limit      int           // RateLimit-Limit
	Remaining  int           // RateLimit-Remaining
	RetryAfter time.Duration // Retry-After (solo si !Allowed)
	ResetAfter time.Duration // RateLimit-Reset (cuándo se libera capacidad)
}

// Limiter evalúa una clave contra una regla. Las implementaciones son atómicas (un solo
// round-trip a Redis vía script Lua) y NUNCA bloquean/duermen: ante exceso devuelven
// Allowed=false + RetryAfter (condición A5).
type Limiter interface {
	Allow(ctx context.Context, key string, rule Rule) (Decision, error)
}

// sliding window log: ZSET con score=timestamp; cuenta los eventos en la última ventana.
// Devuelve {allowed, remaining, retry_ms}.
var slidingWindowScript = redis.NewScript(`
local now    = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit  = tonumber(ARGV[3])
local member = ARGV[4]
redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, now - window)
local count = redis.call('ZCARD', KEYS[1])
if count < limit then
  redis.call('ZADD', KEYS[1], now, member)
  redis.call('PEXPIRE', KEYS[1], window)
  return {1, limit - count - 1, 0}
end
local oldest = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
local retry = window
if oldest[2] then retry = (tonumber(oldest[2]) + window) - now end
if retry < 0 then retry = 0 end
return {0, 0, retry}
`)

// GCRA (Generic Cell Rate Algorithm): ritmo constante con tolerancia de ráfaga (burst).
// Estado = TAT (theoretical arrival time). Devuelve {allowed, remaining, retry_ms}.
var gcraScript = redis.NewScript(`
local now       = tonumber(ARGV[1])
local emission  = tonumber(ARGV[2])
local tolerance = tonumber(ARGV[3])
local tat = tonumber(redis.call('GET', KEYS[1]) or now)
local allow_at = tat - tolerance
if now < allow_at then
  return {0, 0, allow_at - now}
end
local new_tat = math.max(tat, now) + emission
local ttl = math.ceil(new_tat - now + tolerance)
redis.call('SET', KEYS[1], new_tat, 'PX', ttl)
local remaining = math.floor((tolerance - (new_tat - now - emission)) / emission)
if remaining < 0 then remaining = 0 end
return {1, remaining, 0}
`)

// RedisLimiter implementa Limiter sobre Redis. Es la primera dependencia Redis de la
// flota Go, confinada a este paquete (condición A6).
type RedisLimiter struct {
	client redis.Scripter
}

func NewRedisLimiter(client redis.Scripter) *RedisLimiter {
	return &RedisLimiter{client: client}
}

func (l *RedisLimiter) Allow(ctx context.Context, key string, rule Rule) (Decision, error) {
	switch rule.Algorithm {
	case AlgoSlidingWindow:
		return l.runSlidingWindow(ctx, key, rule)
	case AlgoGCRA:
		return l.runGCRA(ctx, key, rule)
	default:
		return Decision{}, fmt.Errorf("algoritmo no soportado: %s", rule.Algorithm)
	}
}

func (l *RedisLimiter) runSlidingWindow(ctx context.Context, key string, rule Rule) (Decision, error) {
	now := time.Now()
	member := strconv.FormatInt(now.UnixNano(), 10)
	res, err := slidingWindowScript.Run(ctx, l.client,
		[]string{key},
		now.UnixMilli(), rule.Window.Milliseconds(), rule.Limit, member,
	).Int64Slice()
	if err != nil {
		return Decision{}, err
	}
	allowed := res[0] == 1
	return Decision{
		Allowed:    allowed,
		Limit:      rule.Limit,
		Remaining:  int(res[1]),
		RetryAfter: time.Duration(res[2]) * time.Millisecond,
		ResetAfter: rule.Window,
	}, nil
}

func (l *RedisLimiter) runGCRA(ctx context.Context, key string, rule Rule) (Decision, error) {
	now := time.Now()
	emission := rule.emissionInterval()
	tolerance := time.Duration(rule.Burst) * emission
	res, err := gcraScript.Run(ctx, l.client,
		[]string{key},
		now.UnixMilli(), emission.Milliseconds(), tolerance.Milliseconds(),
	).Int64Slice()
	if err != nil {
		return Decision{}, err
	}
	allowed := res[0] == 1
	return Decision{
		Allowed:    allowed,
		Limit:      rule.Limit,
		Remaining:  int(res[1]),
		RetryAfter: time.Duration(res[2]) * time.Millisecond,
		ResetAfter: emission,
	}, nil
}
