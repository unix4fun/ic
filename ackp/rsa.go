package ackp

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/unix4fun/ac/acutl"
)

func GenKeysRSA(r io.Reader) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(r, 2048)
}
