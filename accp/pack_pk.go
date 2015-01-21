// +build go1.2
package accp

import (
	"bytes"
	"code.google.com/p/goprotobuf/proto"
	"compress/zlib"
	"encoding/base64"
	//"fmt"
	"github.com/unix4fun/ac/obf"
	"io"
)

//
// PK Message Format:
// BASE64( 'PK' || ZLIB( PUBKEY ) )
//
// We need to encrypt/build encryption
//
func packMessagePK(hdr uint32, blob []byte) (out []byte, err error) {

	acOut := &ACPackedMessage{}
	acOut.Header = &hdr
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

	out = B64EncodeData(acPackedMsg)
	return out, nil
}

//func unpackMessageKX(in []byte) (mNonce uint32, myHdr, dst, ciphertext []byte, err error) {
func unpackMessagePK(in []byte) (ciphertext []byte, err error) {

	acIn := &ACPackedMessage{}

	err = proto.Unmarshal(in, acIn)
	if err != nil {
		return nil, err
	}

	_, err = CheckHeader([]byte(msgHdrPK), acIn.GetHeader())
	if err != nil {
		return nil, err
	}

	//XXX TODO:
	//check for valid source and destination (nicknames) or kex_lame_check here
	//too..

	//XXX TODO more meaningful updates from here...
	//fmt.Printf("Nonce: %d(%08x)\n", acIn.GetNonce(), acIn.GetNonce())
	//return acIn.GetNonce(), myHdr, acIn.GetDst(), acIn.GetCiphertext(), nil
	ciphertext = acIn.GetCiphertext()
	return ciphertext, nil
}

func CreatePKMessageNACL(pubkey []byte) (out []byte, err error) {
	/* lets build our header */
	_, intHdr, err := BuildHeader([]byte(msgHdrPK))
	if err != nil {
		return nil, &protoError{value: -1, msg: "CreatePKMessageNACL().BuildHeader(): ", err: err}
	}

	// first let's compress
	myBody, err := CompressData(pubkey)
	if err != nil {
		return nil, &protoError{value: -2, msg: "CreatePKMessageNACL().CompressData(): ", err: err}
	}

	out, err = packMessagePK(intHdr, myBody)
	if err != nil {
		return nil, &protoError{value: -3, msg: "CreatePKMessageNACL().PackMsg(): ", err: err}
	}

	//fmt.Printf("Pubkey2Irc: %s\n", out)
	return out, nil
}

func OpenPKMessageNACL(ircmsg []byte) (out []byte, err error) {

	b64, err := B64DecodeData(ircmsg)
	if err != nil {
		return nil, &protoError{value: -1, msg: "OpenPKMessageNACL(): ", err: err}
	}

	ciphertext, err := unpackMessagePK(b64)
	if err != nil {
		return nil, &protoError{value: -2, msg: "OpenPKMessageNACL(): ", err: err}
	}

	out, err = DecompressData(ciphertext)
	if err != nil {
		return nil, &protoError{value: -3, msg: "OpenPKMessageNACL(): ", err: err}
	}

	return out, nil
}

//func Pubkey2Irc(pubkey []byte) (out []byte, err error) {
func CreatePKMessage(pubkey []byte) (out []byte, err error) {
	hdr, _ := obf.Obfuscate([]byte(msgHdrPK))
	//fmt.Printf("HEX: %s\n", hex.EncodeToString(hdr))

	body := new(bytes.Buffer)
	zbuf, err := zlib.NewWriterLevel(body, zlib.BestCompression)
	if err != nil {
		//return nil, acprotoError(-1, "CreatePKMessage().zlib.NewWriterLevel(): ", err)
		return nil, &protoError{value: -1, msg: "CreatePKMessage().zlib.NewWriterLevel()", err: err}
	}

	if _, err = zbuf.Write(pubkey); err != nil {
		//return nil, acprotoError(-2, "CreatePKMessage().zlib.Write(): ", err)
		return nil, &protoError{value: -2, msg: "CreatePKMessage().zlib.Write()", err: err}
	}
	zbuf.Close()
	//fmt.Printf("BODY HEX: %s\n", hex.EncodeToString(body.Bytes()))

	buffer := bytes.NewBuffer(hdr)
	_, err = buffer.Write(body.Bytes())
	if err != nil {
		//return nil, acprotoError(-3, "CreatePKMessage().FinalMsg(): ", err)
		return nil, &protoError{value: -3, msg: "CreatePKMessage().FinalMsg()", err: err}
	}

	out = make([]byte, base64.StdEncoding.EncodedLen(len(buffer.Bytes())))
	base64.StdEncoding.Encode(out, buffer.Bytes())

	//fmt.Printf("Pubkey2Irc: %s\n", out)
	return
}

//func Irc2Pubkey(ircmsg []byte) (out []byte, err error) {
func OpenPKMessage(ircmsg []byte) (out []byte, err error) {
	zdata := make([]byte, base64.StdEncoding.DecodedLen(len(ircmsg)))

	datalen, err := base64.StdEncoding.Decode(zdata, ircmsg)
	//data, err := base64.StdEncoding.DecodeString( string(ircmsg) )
	if err != nil || datalen <= 4 {
		//return nil, acprotoError(-1, "OpenPKMessage().B64Decode(): ", err)
		return nil, &protoError{value: -1, msg: "OpenPKMessage().B64Decode(): ", err: err}
		//log.Fatal(err)
		//return
	}
	//    fmt.Printf("DATALEN: %d\n", datalen)

	if datalen < 20 {
		//return nil, acprotoError(-2, "OpenPKMessage().B64Decode(): invalid message size ", nil)
		return nil, &protoError{value: -2, msg: "OpenPKMessage().B64Decode(): invalid message size ", err: nil}
	}

	hdr, err := obf.DeObfuscate(zdata[:4])
	if err != nil {
		//return nil, acprotoError(-3, "OpenPKMessage().Deobfuscate(): invalid message size ", nil)
		return nil, &protoError{value: -3, msg: "OpenPKMessage().Deobfuscate(): invalid message size.", err: err}
	}
	//fmt.Printf("HDR: %s\n", hdr)

	if len(hdr) != 2 {
		//fmt.Printf("WRONG HEADER")
		//return nil, acprotoError(-4, "OpenPKMessage().Hdr(): invalid header", nil)
		return nil, &protoError{value: -4, msg: "OpenPKMessage().Hdr(): invalid header", err: nil}
		//return
	}

	if bytes.Compare(hdr, []byte(msgHdrPK)) != 0 {
		//fmt.Printf("WRONG HEADER")
		//return nil, acprotoError(-5, "OpenPKMessage().Hdr(): invalid header", nil)
		return nil, &protoError{value: -5, msg: "OpenPKMessage().Hdr(): invalid header", err: nil}
		//return
	}

	zbuf := bytes.NewBuffer(zdata[4:])
	data, err := zlib.NewReader(zbuf)
	defer data.Close()
	if err != nil {
		//return nil, acprotoError(-5, "OpenPKMessage().zlib.NewReader(): ", err)
		return nil, &protoError{value: -6, msg: "OpenPKMessage().zlib.NewReader(): ", err: err}
	}
	/*
	   if err != nil {
	       log.Fatal(err)
	       return
	   }
	*/

	b := new(bytes.Buffer)
	_, err = io.Copy(b, data)
	if err != nil {
		//return nil, acprotoError(-6, "OpenPKMessage().io.Copy(): ", err)
		return nil, &protoError{value: -7, msg: "OpenPKMessage().io.Copy(): ", err: err}
		//log.Fatal(err)
		//return
	}

	out = b.Bytes()
	//    data.Read(out)
	//    out, err = ioutil.ReadAll(data)
	//    toto, _ := data.Read(out)
	//    fmt.Printf("toto[1]: %s\n", out)
	//    fmt.Printf("DLSJADLSJSDA : %s\n", zbuf.Bytes())

	return
}
