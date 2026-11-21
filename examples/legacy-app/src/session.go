package session

import (
	"crypto/ecdh"
	"crypto/rand"
)

// NewKey creates an ephemeral key for the partner channel (sample).
func NewKey() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}
