// +build go1.4

// Package ackp implements various key type handlers and associated utility routines
// ackp stands for AC Key Package
package ickp

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"github.com/unix4fun/ic/icutl"
	"golang.org/x/crypto/nacl/box"
	"time"
)

// KexKey describe the internal structure stored in memory for public/private
// key pairs owned or received from peers
type KexKey struct {
	Nickname string
	Userhost string
	Server   string
	Pubkey   string
	HasPriv  bool
	//    Pubfp string // 32 bytes hex encoded string of the hash... XXX we will see if it's problematic later..
	Timestamp int64
	PubFP     [32]byte // 32 bytes hash of the public key...
	CreaTime  time.Time
	pubkey    *[32]byte // 32 bytes TODO: we need to box those info, and unbox them when necessary...
	privkey   *[32]byte // 32 bytes TODO: we need to box those info, and unbox them when necessary...
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
		PubFP, _ := icutl.HashSHA3Data(pubkey)

		// copy and store the public fingerprint..
		copy(pk.PubFP[:], PubFP)
		return nil
	}

	return &icutl.AcError{Value: -1, Msg: "SetPubkeys(weird size): ", Err: nil}
}

// GetPrivkey retrieve and return the private key (privkey) of the current
// AcMyKeys structure.
func (pk *KexKey) GetPrivkey() (privkey *[32]byte) {
	privkey = pk.privkey
	return privkey
}

// GetPubfp retrieve and return the public key fingerprint associated with the
// current key.
func (pk *KexKey) GetPubfp() (PubFP []byte) {
	PubFP = pk.PubFP[:]
	return
}

// if you Println() the struct then it call this as part of the type.
func (pk *KexKey) String() string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "-\n")
	fmt.Fprintf(&b, "KexKey struct @ %p\n", pk)
	fmt.Fprintf(&b, "nick: %s @ %s on %s\n", pk.Nickname, pk.Userhost, pk.Server)
	fmt.Fprintf(&b, "pubkey: %s\n", pk.Pubkey)
	//fmt.Fprintf(&b, "privkey: %s\n", hex.EncodeToString(pk.privkey[:]))
	fmt.Fprintf(&b, "created: %d\n", pk.CreaTime.Unix())
	return b.String()
}

// CreateKxKeys create an KexKey structure using provide randomness source and
// compute the initial EC Ephemeral keypair
// XXX Make sure PRNG is strong.. may be use fortuna...
func CreateKxKeys(nickname, userhost, server string) (mykeys *KexKey, err error) {
	mykeys = new(KexKey)
	mykeys.pubkey, mykeys.privkey, err = box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, &icutl.AcError{Value: -1, Msg: "CreateMyKeys().GenerateKey(): ", Err: err}
	}

	PubFP, err := icutl.HashSHA3Data(mykeys.pubkey[:])
	if err != nil {
		return nil, &icutl.AcError{Value: -2, Msg: "CreateMyKeys().hash(): ", Err: err}
	}

	// copy and store the public fingerprint..
	copy(mykeys.PubFP[:], PubFP)

	/*
		PK, err := CreatePKMessageNACL(mykeys.pubkey[:])
		if err != nil {
			//return nil, acprotoError(-3, "CreateMyKeys().CreatePKMessage(): ", err)
			return nil, &icutl.AcError{Value: -3, Msg: "CreateMyKeys().CreatePKMessage(): ", Err: err}
		}
		mykeys.Pubkey = string(PK)
	*/
	mykeys.Nickname = nickname
	mykeys.Userhost = userhost
	mykeys.Server = server
	mykeys.HasPriv = true
	mykeys.CreaTime = time.Now()
	mykeys.Timestamp = mykeys.CreaTime.Unix()

	return mykeys, nil
}

// XXX TODO: to reimplement properly..
func CreateKxKeys2(nickname, userhost, server string) (*KexKey, error) {
	/*
		pubkey, privkey, err := box.GenerateKey(rand.Reader)
		if err != nil {
			return nil, &icutl.AcError{Value: -1, Msg: "CreateMyKeys().GenerateKey(): ", Err: err}
		}

		PubFP, err := icutl.HashSHA3Data(pubkey[:])
	*/
	return nil, nil

}
