package domain

import "time"

// RetryPolicy defines exponential backoff and DLQ thresholds.
type RetryPolicy struct {
	MaxAttempts   int
	InitialDelay  time.Duration
	MaxDelay      time.Duration
	BackoffFactor float64
}

// DefaultRetryPolicy returns a sensible default.
func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{
		MaxAttempts:   5,
		InitialDelay:  1 * time.Second,
		MaxDelay:      5 * time.Minute,
		BackoffFactor: 2.0,
	}
}

// ComputeDelay returns the delay before the next attempt (1-based).
func (p RetryPolicy) ComputeDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > p.MaxAttempts {
		attempt = p.MaxAttempts
	}
	factor := time.Duration(float64(p.InitialDelay) * pow(p.BackoffFactor, float64(attempt-1)))
	if factor > p.MaxDelay {
		factor = p.MaxDelay
	}
	// Add small jitter to avoid thundering herd.
	jitter := time.Duration(randInt63n(int64(factor / 10)))
	return factor + jitter
}

func pow(base, exp float64) float64 {
	result := 1.0
	for i := 0; i < int(exp); i++ {
		result *= base
	}
	return result
}
