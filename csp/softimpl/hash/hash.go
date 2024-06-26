package hash

import (
	"hash"

	"github.com/11090815/mayy/csp"
)

type Hasher struct {
	hash func() hash.Hash
}

func NewHasher(hash func() hash.Hash) *Hasher {
	return &Hasher{hash: hash}
}

func (h *Hasher) Hash(msg []byte, opts csp.HashOpts) ([]byte, error) {
	hashFunc := h.hash()
	hashFunc.Write(msg)
	return hashFunc.Sum(nil), nil
}

func (h *Hasher) GetHash(opts csp.HashOpts) (hash.Hash, error) {
	return h.hash(), nil
}
