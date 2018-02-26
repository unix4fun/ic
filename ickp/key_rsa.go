package ickp

import (
	//"crypto/rand"
	"crypto/rsa"
	//"github.com/unix4fun/ac/acutl"
	"io"
)

const (
	KEYSIZE_RSA = 4096
)

func GenKeysRSA(r io.Reader) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(r, KEYSIZE_RSA)
}
