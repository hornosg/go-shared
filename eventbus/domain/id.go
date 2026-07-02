package domain

import (
	"encoding/hex"
	"math/rand"
	"time"
)

// GenerateID returns a UUID-like identifier using random bytes.
// Exported so application use cases can assign event IDs when missing.
func GenerateID() string {
	b := make([]byte, 16)
	binaryRead(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return hex.EncodeToString(b[:4]) + "-" +
		hex.EncodeToString(b[4:6]) + "-" +
		hex.EncodeToString(b[6:8]) + "-" +
		hex.EncodeToString(b[8:10]) + "-" +
		hex.EncodeToString(b[10:16])
}

func binaryRead(b []byte) {
	_, err := rand.Read(b)
	if err != nil {
		// Fallback: fill with time-based pseudo-random bytes.
		src := rand.New(rand.NewSource(time.Now().UnixNano()))
		for i := range b {
			b[i] = byte(src.Intn(256))
		}
	}
}
