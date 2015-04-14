// +build go1.4
// accp == AC Crypto Protocol
package accp

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/nacl/box"       // nacl is now here.
	"golang.org/x/crypto/nacl/secretbox" // nacl is now here.
	"io"
	"time"
)

/*
 * Here we start the protocol definition
 */

const (
	msgHdrPK = "PK"
	msgHdrAC = "AC"
	msgHdrKX = "KX"
)

// protoError is the custom AC error type
// exporting the error code ad well as string and cascaded error message
type protoError struct {
	value int    // the error code.
	msg   string // the associated message
	err   error  // called layer error
}

func (ae *protoError) Error() string {
	if ae.err != nil {
		ae.msg = fmt.Sprintf("protoError[%d]: %s:%s\n", ae.value, ae.msg, ae.err.Error())
	} else {
		ae.msg = fmt.Sprintf("protoError[%d]: %s\n", ae.value, ae.msg)
	}
	return ae.msg
}

/*
func (ae *protoError) getErrorCode() int {
	return ae.value
}

func (ae *protoError) getErrorMsg() string {
	return ae.Error()
}

func acprotoError(val int, msg string, err error) (ae *protoError) {
	return &protoError{value: val, msg: msg, err: err}
}
*/

// CreateMyKeys create an KexKey structure using provide randomness source and
// compute the initial EC Ephemeral keypair
// XXX Make sure PRNG is strong.. may be use fortuna...
func CreateMyKeys(rnd io.Reader, nickname, userhost, server string) (mykeys *ackp.KexKey, err error) {
	mykeys = new(ackp.KexKey)
	mykeys.pubkey, mykeys.privkey, err = box.GenerateKey(rand.Reader)
	if err != nil {
		//return nil, acprotoError(-1, "CreateMyKeys().GenerateKey(): ", err)
		return nil, &protoError{value: -1, msg: "CreateMyKeys().GenerateKey(): ", err: err}
	}

	pubfp, err := HashSHA3Data(mykeys.pubkey[:])
	if err != nil {
		//return nil, acprotoError(-1, "CreateMyKeys().hash(): ", err)
		return nil, &protoError{value: -2, msg: "CreateMyKeys().hash(): ", err: err}
	}

	// copy and store the public fingerprint..
	copy(mykeys.pubfp[:], pubfp)

	PK, err := CreatePKMessageNACL(mykeys.pubkey[:])
	if err != nil {
		//return nil, acprotoError(-3, "CreateMyKeys().CreatePKMessage(): ", err)
		return nil, &protoError{value: -3, msg: "CreateMyKeys().CreatePKMessage(): ", err: err}
	}
	mykeys.Pubkey = string(PK)
	mykeys.Nickname = nickname
	mykeys.Userhost = userhost
	mykeys.Server = server
	mykeys.HasPriv = true
	mykeys.CreaTime = time.Now()

	return mykeys, nil
}

func CreateACContext(channel []byte, nonce uint32) (context *ackp.SecKey, err error) {
	context = new(ackp.SecKey)
	// TODO XXX: we need to be careful after a key exchange we can re-encrypt a
	// message with the same nonce, so we should give the nonce with the KEX
	// and also update the nonce on every received message
	context.nonce = nonce
	context.bob = channel
	context.key = new([32]byte)
	context.Overhead = secretbox.Overhead
	return context, nil
}

func CreateACContextWithInputEntropy(channel []byte, inputEntropy []byte) (context *ackp.SecKey, err error) {
	context = new(ackp.SecKey)
	context.nonce = 0
	context.bob = channel
	context.Overhead = secretbox.Overhead

	shaEntropy, err := HashSHA3Data(inputEntropy)
	if err != nil {
		//return nil, acprotoError(-1, "CreateACContextWithInputEntropy().HashSHA3Data(): ", err)
		return nil, &protoError{value: -1, msg: "CreateACContextWithInputEntropy().HashSHA3Data(): ", err: err}
	}
	copy(context.key[:], shaEntropy)
	return context, nil
}
