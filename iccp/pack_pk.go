// +build go1.4
package iccp

import (
	//	"bytes"
	//	"compress/zlib"
	//	"encoding/base64"
	//"fmt"
	"github.com/golang/protobuf/proto" // protobuf is now here.
	"github.com/unix4fun/ic/icutl"
	//	"io"
)

//
// PK Message Format:
// BASE64( 'PK' || ZLIB( PUBKEY ) )
//
// We need to encrypt/build encryption
//
//func packMessagePK(hdr uint32, blob []byte) (out []byte, err error) {
func packMessagePK(blob []byte) (out []byte, err error) {

	acOut := &ACPackedMessage{}

	_, intHdr, err := BuildHeader([]byte(msgHdrPK))
	if err != nil {
		return nil, err ///&icutl.AcError{Value: -1, Msg: "CreatePKMessageNACL().BuildHeader(): ", Err: err}
	}

	//acOut.Header = hdr
	acOut.Header = intHdr
	//acOut.Nonce = proto.Uint32(*nonce)
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

	out = icutl.B64EncodeData(acPackedMsg)
	return out, nil
}

//func unpackMessageKX(in []byte) (mNonce uint32, myHdr, dst, ciphertext []byte, err error) {
func unpackMessagePK(in []byte) (ciphertext []byte, err error) {

	acIn := &ACPackedMessage{}

	b64, err := icutl.B64DecodeData(in)
	if err != nil {
		return nil, err //&icutl.AcError{Value: -1, Msg: "OpenPKMessageNACL(): ", Err: err}
	}

	err = proto.Unmarshal(b64, acIn)
	if err != nil {
		return nil, err
	}

	_, err = CheckHeader([]byte(msgHdrPK), acIn.Header)
	if err != nil {
		return nil, err
	}

	//XXX TODO:
	//check for valid source and destination (nicknames) or kex_lame_check here
	//too..

	//XXX TODO more meaningful updates from here...
	//fmt.Printf("Nonce: %d(%08x)\n", acIn.GetNonce(), acIn.GetNonce())
	//return acIn.GetNonce(), myHdr, acIn.GetDst(), acIn.GetCiphertext(), nil
	ciphertext = acIn.Ciphertext
	return ciphertext, nil
}

func CreatePKMessageNACL(pubkey []byte) (out []byte, err error) {
	/* lets build our header */
	/*
		_, intHdr, err := BuildHeader([]byte(msgHdrPK))
		if err != nil {
			return nil, &icutl.AcError{Value: -1, Msg: "CreatePKMessageNACL().BuildHeader(): ", Err: err}
		}
	*/

	// first let's compress
	myBody, err := icutl.CompressData(pubkey)
	if err != nil {
		return nil, &icutl.AcError{Value: -2, Msg: "CreatePKMessageNACL().CompressData(): ", Err: err}
	}

	//out, err = packMessagePK(intHdr, myBody)
	out, err = packMessagePK(myBody)
	if err != nil {
		return nil, &icutl.AcError{Value: -3, Msg: "CreatePKMessageNACL().PackMsg(): ", Err: err}
	}

	//fmt.Printf("Pubkey2Irc: %s\n", out)
	return out, nil
}

func OpenPKMessageNACL(ircmsg []byte) (out []byte, err error) {

	/*
		b64, err := icutl.B64DecodeData(ircmsg)
		if err != nil {
			return nil, &icutl.AcError{Value: -1, Msg: "OpenPKMessageNACL(): ", Err: err}
		}
	*/

	//ciphertext, err := unpackMessagePK(b64)
	ciphertext, err := unpackMessagePK(ircmsg)
	if err != nil {
		return nil, &icutl.AcError{Value: -2, Msg: "OpenPKMessageNACL(): ", Err: err}
	}

	out, err = icutl.DecompressData(ciphertext)
	if err != nil {
		return nil, &icutl.AcError{Value: -3, Msg: "OpenPKMessageNACL(): ", Err: err}
	}

	return out, nil
}
