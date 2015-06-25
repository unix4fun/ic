package ackp

import (
	//"crypto/rand"
	"github.com/agl/ed25519"
	//"github.com/unix4fun/ac/acutl"
	"crypto"
	"io"
)

type Ed25519PrivateKey struct {
	Pub  *[ed25519.PublicKeySize]byte
	Priv *[ed25519.PrivateKeySize]byte
}

//
// TODO: need to implement type Signer interface
//       which mean we need Public() and Sign()
func GenKeysED25519(r io.Reader) (*Ed25519PrivateKey, error) {
	var err error

	k := new(Ed25519PrivateKey)
	pub, priv, err := ed25519.GenerateKey(r)
	if err != nil {
		return nil, err
	}
	k.Pub = pub
	k.Priv = priv
	return k, nil
}

func (priv *Ed25519PrivateKey) Public() crypto.PublicKey {
	return priv.Pub
}

func (priv *Ed25519PrivateKey) Sign(r io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	signature := ed25519.Sign(priv.Priv, msg)
	return (*signature)[:], nil
}
