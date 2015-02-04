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

// KexKey describe the internal structure stored in memory for public/private
// key pairs owned or received from peers
type KexKey struct {
	Nickname string
	Userhost string
	Server   string
	Pubkey   string
	HasPriv  bool
	//    Pubfp string // 32 bytes hex encoded string of the hash... XXX we will see if it's problematic later..
	CreaTime time.Time
	pubfp    [32]byte  // 32 bytes hash of the public key...
	pubkey   *[32]byte // 32 bytes TODO: we need to box those info, and unbox them when necessary...
	privkey  *[32]byte // 32 bytes TODO: we need to box those info, and unbox them when necessary...
}

// GetPubkey retrieve and return the public key component from the current KexKey structure.
func (pk *KexKey) GetPubkey() (pubkey *[32]byte) {
	pubkey = pk.pubkey
	return
}

// SetPubkey writes the argument provided public key (pubkey) of the current
// AcMyKeys structure.
func (pk *KexKey) SetPubkey(pubkey []byte) error {
	if len(pubkey) == 32 {
		pk.pubkey = new([32]byte)
		copy(pk.pubkey[:], pubkey)

		// XXX TODO: handle error here...
		pubfp, _ := HashSHA3Data(pubkey)

		// copy and store the public fingerprint..
		copy(pk.pubfp[:], pubfp)
		return nil
	}

	return &protoError{value: -1, msg: "SetPubkeys(weird size): ", err: nil}
}

// GetPrivkey retrieve and return the private key (privkey) of the current
// AcMyKeys structure.
func (pk *KexKey) GetPrivkey() (privkey *[32]byte) {
	privkey = pk.privkey
	return privkey
}

// GetPubfp retrieve and return the public key fingerprint associated with the
// current key.
func (pk *KexKey) GetPubfp() (pubfp []byte) {
	pubfp = pk.pubfp[:]
	return
}

// if you Println() the struct then it call this as part of the type.
func (pk *KexKey) String() string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "----\n")
	fmt.Fprintf(&b, "KexKey struct @ %p\n", pk)
	fmt.Fprintf(&b, "nick: %s @ %s on %s\n", pk.Nickname, pk.Userhost, pk.Server)
	fmt.Fprintf(&b, "pubkey: %s\n", pk.Pubkey)
	//fmt.Fprintf(&b, "privkey: %s\n", hex.EncodeToString(pk.privkey[:]))
	fmt.Fprintf(&b, "created: %l\n", pk.CreaTime.Unix())
	return b.String()
}

type SecKey struct {
	nonce    uint32
	bob      []byte
	key      [32]byte
	CreaTime time.Time
	Overhead int
}

// if you Println() the struct then it call this as part of the type.
func (sk *SecKey) String() string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "----\n")
	fmt.Fprintf(&b, "SecKey struct @ %p\n", sk)
	fmt.Fprintf(&b, "-> bob : %s\n", sk.bob)
	fmt.Fprintf(&b, "-> key : %s\n", hex.EncodeToString(sk.key[:]))
	fmt.Fprintf(&b, "-> nonce : %08x\n", sk.nonce)
	fmt.Fprintf(&b, "-> created: %l\n", sk.CreaTime.Unix())
	return b.String()
}

func (sk *SecKey) GetKey() []byte {
	// XXX TODO here we will be able to get the memory encrypted key instead of
	// plain.
	return sk.key[:]
}

func (sk *SecKey) SetKey(keydata []byte) {
	copy(sk.key[:], keydata[:32])
	return
}

func (sk *SecKey) GetNonce() uint32 {
	return sk.nonce
}

// CreateMyKeys create an KexKey structure using provide randomness source and
// compute the initial EC Ephemeral keypair
// XXX Make sure PRNG is strong.. may be use fortuna...
func CreateMyKeys(rnd io.Reader, nickname, userhost, server string) (mykeys *KexKey, err error) {
	mykeys = new(KexKey)
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

func CreateACContext(channel []byte, nonce uint32) (context *SecKey, err error) {
	context = new(SecKey)
	// TODO XXX: we need to be careful after a key exchange we can re-encrypt a
	// message with the same nonce, so we should give the nonce with the KEX
	// and also update the nonce on every received message
	context.nonce = nonce
	context.bob = channel
	context.Overhead = secretbox.Overhead
	return context, nil
}

func CreateACContextWithInputEntropy(channel []byte, inputEntropy []byte) (context *SecKey, err error) {
	context = new(SecKey)
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
