// +build go1.4
// accp == AC Crypto Protocol
package accp

import (
	//"bytes"
	//"crypto/rand"
	//"encoding/hex"
	//"fmt"
	//"golang.org/x/crypto/nacl/box"       // nacl is now here.
	"github.com/unix4fun/ac/ackp"
	"github.com/unix4fun/ac/acutl"
	"golang.org/x/crypto/nacl/secretbox" // nacl is now here.
	//"io"
	//"time"
)

/*
 * Here we start the protocol definition
 */

const (
	msgHdrPK = "PK"
	msgHdrAC = "AC"
	msgHdrKX = "KX"
)

func CreateACContextWithInputEntropy(channel []byte, inputEntropy []byte) (context *ackp.SecretKey, err error) {
	context = new(ackp.SecretKey)

	context.SetNonce(0)
	//context.nonce = 0
	context.SetBob(channel)
	//context.bob = channel
	context.Overhead = secretbox.Overhead

	shaEntropy, err := acutl.HashSHA3Data(inputEntropy)
	if err != nil {
		//return nil, acprotoError(-1, "CreateACContextWithInputEntropy().HashSHA3Data(): ", err)
		return nil, &acutl.AcError{Value: -1, Msg: "CreateACContextWithInputEntropy().HashSHA3Data(): ", Err: err}
	}

	context.SetKey(shaEntropy)
	//copy(context.key[:], shaEntropy)
	return context, nil
}
