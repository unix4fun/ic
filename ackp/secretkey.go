// +build go1.4

package ackp

import (
	"bytes"
	//"crypto/rand"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/nacl/secretbox"
	"time"
	//"debug/elf"
)

type SecKey struct {
	Nonce uint32 `json:"nonce"`
	Bob []byte `json:"bob"`
	Key *[32]byte `json:"key"`
	CreaTime time.Time `json:"creatime"`
	Overhead int `json:"overhead"`
}

// if you Println() the struct then it call this as part of the type.
func (sk *SecKey) String() string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "-\n")
	fmt.Fprintf(&b, "SecKey struct @ %p\n", sk)
	fmt.Fprintf(&b, "-> bob : %s\n", sk.Bob)
	fmt.Fprintf(&b, "-> key : %s\n", hex.EncodeToString(sk.Key[:]))
	fmt.Fprintf(&b, "-> nonce : %08x\n", sk.Nonce)
	fmt.Fprintf(&b, "-> created: %d\n", sk.CreaTime.Unix())
	return b.String()
}

func (sk *SecKey) GetKey() []byte {
	// XXX TODO here we will be able to get the memory encrypted key instead of
	// plain.
	return sk.Key[:]
}

func (sk *SecKey) NewKey() {
	sk.Key = new([32]byte)
}
func (sk *SecKey) GetKeyLen() int {
	return len(sk.Key)
}

func (sk *SecKey) GetSealKey() *[32]byte {
	return sk.Key
}

func (sk *SecKey) SetKey(keydata []byte) {
	copy(sk.Key[:], keydata[:32])
	return
}

func (sk *SecKey) SetNonce(nonce uint32) {
	sk.Nonce = nonce
}

func (sk *SecKey) GetNonce() uint32 {
	return sk.Nonce
}

func (sk *SecKey) SetBob(bob []byte) {
	sk.Bob = bob
}
func (sk *SecKey) GetBob() []byte {
	return sk.Bob
}

func (sk *SecKey) IncNonce(n uint32) {
	//sk.nonce++
	if n > sk.Nonce {
		sk.Nonce = n + 1
	} else {
		sk.Nonce++
	}
}

func (sk *SecKey) RndKey(rnd []byte) {
	// OPEN the key
	// XXX new to check rnd and context.key are the same size
	for j := 0; j < len(rnd); j++ {
		sk.Key[j] = sk.Key[j] ^ rnd[j]
	}
}

func CreateACContext(channel []byte, nonce uint32) (context *SecKey, err error) {
	context = new(SecKey)
	// TODO XXX: we need to be careful after a key exchange we can re-encrypt a
	// message with the same nonce, so we should give the nonce with the KEX
	// and also update the nonce on every received message
	context.SetNonce(nonce)
	//context.nonce = nonce
	context.SetBob(channel)
	//context.bob = channel
	context.NewKey()
	//context.key = new([32]byte)
	// XXX this is message dependent and not algo dependent as each message can be using different algos
	context.Overhead = secretbox.Overhead
	return context, nil
}
