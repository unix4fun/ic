package ackp

import (
	//"crypto/rand"
	"github.com/agl/ed25519"
	//"github.com/unix4fun/ac/acutl"
	"io"
)

type Ed25519PrivateKey struct {
	pub  *[ed25519.PublicKeySize]byte
	priv *[ed25519.PrivateKeySize]byte
}

func GenKeysED25519(r io.Reader) (*Ed25519PrivateKey, error) {
	var err error

	k := new(Ed25519PrivateKey)
	pub, priv, err := ed25519.GenerateKey(r)
	if err != nil {
		return nil, err
	}
	k.pub = pub
	k.priv = priv
	return k, nil
}
