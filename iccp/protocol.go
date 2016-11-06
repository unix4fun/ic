// +build go1.5

// iccp == IC(4f) C(rypto) P(rotocol)
package iccp

import (
	"github.com/unix4fun/ic/ickp"
	"github.com/unix4fun/ic/icutl"
	"golang.org/x/crypto/nacl/secretbox" // nacl is now here.
)

/*
 * Here we start the protocol definition
 */

const (
	msgHdrPK = "PK"
	msgHdrAC = "AC"
	msgHdrKX = "KX"
)

func CreateACContextWithInputEntropy(channel []byte, inputEntropy []byte) (context *ickp.SecretKey, err error) {
	context = new(ickp.SecretKey)

	context.SetNonce(0)
	//context.nonce = 0
	context.SetBob(channel)
	//context.bob = channel
	context.Overhead = secretbox.Overhead

	shaEntropy, err := icutl.HashSHA3Data(inputEntropy)
	if err != nil {
		//return nil, acprotoError(-1, "CreateACContextWithInputEntropy().HashSHA3Data(): ", err)
		return nil, &icutl.AcError{Value: -1, Msg: "CreateACContextWithInputEntropy().HashSHA3Data(): ", Err: err}
	}

	context.SetKey(shaEntropy)
	//copy(context.key[:], shaEntropy)
	return context, nil
}
