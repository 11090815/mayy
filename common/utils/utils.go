package utils

import (
	"github.com/11090815/mayy/csp/factory"
	"github.com/11090815/mayy/csp/softimpl/hash"
)

// ConcatenateBytes 将给定的若干个字节数组拼接到一起。
func ConcatenateBytes(data ...[]byte) []byte {
	finalLength := 0
	for _, slice := range data {
		finalLength += len(slice)
	}
	result := make([]byte, finalLength)
	last := 0
	for _, slice := range data {
		for i := range slice {
			result[i+last] = slice[i]
		}
		last += len(slice)
	}
	return result
}

func ComputeSHA256(data []byte) []byte {
	csp, err := factory.GetCSP()
	if err != nil {
		panic(err)
	}
	hash, err := csp.Hash(data, &hash.SHA256Opts{})
	if err != nil {
		panic(err)
	}
	return hash
}
