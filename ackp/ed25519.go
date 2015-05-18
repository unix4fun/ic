package ackp

import (
	"crypto/rand"
	"github.com/agl/ed25519"
	"github.com/unix4fun/ac/acutl"
)

type PrivateKey struct {
	pub  *[ed25519.PublicKeySize]byte
	priv *[ed25519.PrivateKeySize]byte
}

func GenKeysED25519(r io.Reader) (k *PrivateKey, err error) {
	k := new(PrivateKey)
	k.pub, k.priv, err = ed25519.GenerateKey(r)
	if err != nil {
		return nil, err
	}
	return k, nil
}
