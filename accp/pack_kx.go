// +build go1.4
package accp

import (
	"bytes"
	"fmt"
	"github.com/golang/protobuf/proto" // protobuf is now here.
	"github.com/unix4fun/ac/ackp"
	"github.com/unix4fun/ac/acutl"
	"golang.org/x/crypto/nacl/box" // nacl is now here.
	"os"
)

func packMessageKX(hdr *uint32, nonce uint32, dst, blob []byte) (out []byte, err error) {

	acOut := &ACPackedMessage{}
	acOut.Header = hdr
	acOut.Nonce = proto.Uint32(nonce)
	//acOut.Dst = dst
	acOut.Ciphertext = blob

	//fmt.Printf("Nonce: %d(%08x)\n", nonce, nonce)

	acPackedMsg, err := proto.Marshal(acOut)
	if err != nil {
		return nil, err
	}
	// XXX test for errors message..
	//fmt.Printf("AC Message TEST #1 : %d (%v)\n", len(acPackedMsg), err)
	//fmt.Printf("PACKED: %s\n", hex.EncodeToString(acPackedMsg))

	out = acutl.B64EncodeData(acPackedMsg)
	return out, nil
}

//func unpackMessageKX(in []byte) (mNonce uint32, myHdr, dst, ciphertext []byte, err error) {
func unpackMessageKX(in []byte) (mNonce uint32, myHdr, ciphertext []byte, err error) {

	acIn := &ACPackedMessage{}
	err = proto.Unmarshal(in, acIn)
	if err != nil {
		return 0, nil, nil, err
	}

	myHdr, err = CheckHeader([]byte(msgHdrKX), acIn.GetHeader())
	if err != nil {
		return 0, nil, nil, err
	}

	//XXX TODO:
	//check for valid source and destination (nicknames) or kex_lame_check here
	//too..

	//XXX TODO more meaningful updates from here...
	//fmt.Printf("Nonce: %d(%08x)\n", acIn.GetNonce(), acIn.GetNonce())
	//return acIn.GetNonce(), myHdr, acIn.GetDst(), acIn.GetCiphertext(), nil
	return acIn.GetNonce(), myHdr, acIn.GetCiphertext(), nil
}

func IsChannelOrPriv(channel, myNick, peerNick []byte) []byte {
	// XXX this handle the fact that it is a channel or a private message, it is
	// very IRC specific as such, think again before modifying the format, you
	// might break the crypto too...
	kx_channel := channel
	ok_channel, _ := IsValidChannelName(kx_channel)
	fmt.Fprintf(os.Stderr, "[+] IsChannelOrPriv(): is %s a valid channel: %t\n", kx_channel, ok_channel)
	if ok_channel == false {
		//kx_channel := channel
		// nonce building!
		kxc_build := new(bytes.Buffer)
		kxc_build.Write([]byte(myNick))
		kxc_build.WriteByte(byte('='))
		kxc_build.Write([]byte(peerNick))
		kx_channel = kxc_build.Bytes()
		fmt.Fprintf(os.Stderr, "[+] IsChannelOrPriv: not a channel, private conversation let's use this: %s\n", kx_channel)
	}
	return kx_channel
}

//
// KX (Key eXchange) Message Format:
// BASE64( 'KX' || 'NONCE_VALUE' || BOX( PEER_PUBKEY, ME_PRIVKEY, NONCE_AUTH, ZLIB( SECRET ) )
//
// Nonce AUTH Format:
// SHA3( 'CHANNEL' || ':' || 'MY_NICK' || ':' || 'PEER_NICK' || ':' || 'NONCE_VALUE' || ':' || 'HDR_RAW' )
//

func CreateKXMessageNACL(context *ackp.SecretKey, rnd []byte, peerPubkey, myPrivkey *[32]byte, channel, myNick, peerNick []byte) (out []byte, err error) {

	/* lets build our header */
	myHdr, intHdr, err := BuildHeader([]byte(msgHdrKX))
	if err != nil {
		return nil, &acutl.AcError{Value: -1, Msg: "CreateKXMessageNACL().BuildHeader(): ", Err: err}
	}

	// Open the key
	context.RndKey(rnd)

	//fmt.Fprintf(os.Stderr, "CREATE KX KEY: %s\n", hex.EncodeToString(context.key[:]))
	// first let's compress
	myBody, err := acutl.CompressData(context.GetKey())
	if err != nil {
		return nil, &acutl.AcError{Value: -2, Msg: "CreateKXMessageNACL().CompressData(): ", Err: err}
	}

	// Close the key
	context.RndKey(rnd)

	//fmt.Fprintf(os.Stderr, "channel: %s context.bob: %s\n", channel, context.bob)

	kx_channel := IsChannelOrPriv(channel, myNick, peerNick)
	// XXX i can probably use context.bob instead of a specific channel specification...
	//BuildNonceAC(inonce uint32, bob, mynick, myhdr []byte) (nonce []byte, noncebyte *[24]byte, err error)
	_, noncebyte, err := BuildNonceKX(context.GetNonce(), kx_channel, myNick, peerNick, myHdr)

	//fmt.Fprintf(os.Stderr, "peerpk : %p myprivkey: %p\n", peerPubkey, myPrivkey)
	// XXX TODO: need serious cleanup and error checking!!
	//fmt.Fprintf(os.Stderr, "body.Bytes(): %p, noncebyte: %p, peerPub: %p myPriv: %p\n", myBody, &noncebyte, peerPubkey, myPrivkey)
	cipherKex := box.Seal(nil, myBody, noncebyte, peerPubkey, myPrivkey)

	//func packMessageKX(hdr, nonce *uint32, dst, blob *[]byte) (out []byte, err error) {
	out, err = packMessageKX(&intHdr, context.GetNonce(), peerNick, cipherKex)
	if err != nil {
		return nil, &acutl.AcError{Value: -3, Msg: "CreateKXMessageNACL().packMessageKX(): ", Err: err}
	}

	//context.nonce++
	context.IncNonce(0)
	return
}

func OpenKXMessageNACL(peerPubkey, myPrivkey *[32]byte, cmsg, channel, myNick, peerNick []byte) (context *ackp.SecretKey, SecRnd []byte, err error) {
	// check that we are indeed
	if peerPubkey == nil || myPrivkey == nil {
		//return nil, acprotoError(-1, "OpenKXMessage().invalidPubPrivKeys(): ", err)
		return nil, nil, &acutl.AcError{Value: -1, Msg: "OpenKXMessageNACL().invalidPubPrivKeys(): ", Err: err}
	}

	b64, err := acutl.B64DecodeData(cmsg)
	if err != nil {
		return nil, nil, &acutl.AcError{Value: -2, Msg: "OpenKXMessageNACL(): ", Err: err}
	}

	cnonce, myHdr, ciphertext, err := unpackMessageKX(b64)
	if err != nil {
		return nil, nil, &acutl.AcError{Value: -3, Msg: "OpenKXMessageNACL(): ", Err: err}
	}

	// XXX TODO: exact opposite of the one in CreateKXMessage
	kx_channel := IsChannelOrPriv(channel, peerNick, myNick)

	// XXX TODO: we should add the header like <ackx:peerNick> to avoid replay from
	// other nickname on the channel... nonce building!
	_, noncebyte, err := BuildNonceKX(cnonce, kx_channel, peerNick, myNick, myHdr)
	if err != nil {
		return nil, nil, &acutl.AcError{Value: -4, Msg: "OpenKXMessageNACL(): ", Err: err}
	}

	packed, ok := box.Open(nil, ciphertext, noncebyte, peerPubkey, myPrivkey)
	if ok == false {
		return nil, nil, &acutl.AcError{Value: -5, Msg: "OpenKXMessageNACL().BoxOpen(): ", Err: nil}
	}

	out, err := acutl.DecompressData(packed)
	if err != nil {
		return nil, nil, &acutl.AcError{Value: -6, Msg: "OpenKXMessageNACL(): ", Err: err}
	}

	//fmt.Fprintf(os.Stderr, "OPEN KX KEY: %s\n", hex.EncodeToString(out))
	// XXX TODO are we at the end of the nonce value..
	context, err = ackp.CreateACContext(channel, cnonce+1)
	if err != nil {
		return nil, nil, &acutl.AcError{Value: -7, Msg: "OpenKXMessage().CreateACContext(): ", Err: err}
	}

	// XXX TODO
	// get RANDOMNESS bytes, return the random bytes
	newRnd, err := acutl.GetRandomBytes(context.GetKeyLen())
	if err != nil {
		return nil, nil, &acutl.AcError{Value: -8, Msg: "OpenKXMessage() no randomness to protect the key in memory: ", Err: err}
	}
	/*
		newRnd := make([]byte, len(context.key))
		_, err = rand.Read(newRnd)
	*/

	// XXX TODO: check the extracted buffer size... to sure we're not copying
	// too much into a restricted buffer...
	//copy(context.key[:], out)
	context.SetKey(out)

	// Xor the key now..
	context.RndKey(newRnd)

	// increase nonce based on the message nonce value
	context.IncNonce(cnonce)

	return context, newRnd, nil
}
