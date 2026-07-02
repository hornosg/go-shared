package domain

import (
	"math/rand"
	"sync"
	"time"
)

var randMu sync.Mutex
var globalRand = rand.New(rand.NewSource(time.Now().UnixNano()))

// randInt63n returns a non-negative pseudo-random int64 in [0,n). It is safe
// for concurrent use.
func randInt63n(n int64) int64 {
	randMu.Lock()
	defer randMu.Unlock()
	return globalRand.Int63n(n)
}
