package ackp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"github.com/unix4fun/ac/acutl"
)

func GenKeysECDSA(r io.Reader) (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), r)
}
