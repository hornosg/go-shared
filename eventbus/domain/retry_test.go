package domain

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRetryPolicyComputeDelay(t *testing.T) {
	policy := RetryPolicy{
		MaxAttempts:   5,
		InitialDelay:  1 * time.Second,
		MaxDelay:      30 * time.Second,
		BackoffFactor: 2.0,
	}

	d1 := policy.ComputeDelay(1)
	assert.GreaterOrEqual(t, d1, 1*time.Second)
	assert.Less(t, d1, 2*time.Second)

	d2 := policy.ComputeDelay(2)
	assert.GreaterOrEqual(t, d2, 2*time.Second)
	assert.Less(t, d2, 4*time.Second)

	d5 := policy.ComputeDelay(5)
	assert.GreaterOrEqual(t, d5, 16*time.Second)
	assert.Less(t, d5, 32*time.Second)
}

func TestRetryPolicyMaxDelayCaps(t *testing.T) {
	policy := RetryPolicy{
		MaxAttempts:   10,
		InitialDelay:  1 * time.Second,
		MaxDelay:      2 * time.Second,
		BackoffFactor: 10.0,
	}

	d := policy.ComputeDelay(10)
	assert.GreaterOrEqual(t, d, 2*time.Second)
	assert.Less(t, d, 3*time.Second) // includes jitter
}

func TestPow(t *testing.T) {
	assert.InDelta(t, 8.0, pow(2.0, 3), 0.0001)
	assert.InDelta(t, 1.0, pow(5.0, 0), 0.0001)
}
