package utils

import (
	"math/rand"
	"time"
)

var random = rand.New(rand.NewSource(time.Now().UnixNano()))

func RandomUint64() uint64 {
	return random.Uint64()
}

func RandomIntn(n int) int {
	return random.Intn(n)
}
