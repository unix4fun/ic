// +build go1.5

package iccp

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/unix4fun/ic/icutl"
	"github.com/unix4fun/ic/obf"
	"os"
	"regexp"
)

func Nonce2Byte(nonce uint32) []byte {
	// we KNOW the nonce is 32 bits but if we move to protobuf we can may be
	// switch it to 64 bits as protobuf will optimize
	NonceBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(NonceBuf, nonce)
	return NonceBuf
}

func Byte2Nonce(nonceBuf []byte) uint32 {
	return binary.LittleEndian.Uint32(nonceBuf)
}

func nonceBuildAC(bob, myNick, myCounter, msgHdr []byte) (out []byte, err error) {
	nonceBuild := new(bytes.Buffer)

	bobHash, bobErr := icutl.HashSHA3Data(bob)
	if bobErr != nil {
		return nil, &icutl.AcError{Value: -1, Msg: "NonceBuildAC().bobHash(): ", Err: bobErr}
	}

	nickHash, nickErr := icutl.HashSHA3Data(myNick)
	if nickErr != nil {
		return nil, &icutl.AcError{Value: -1, Msg: "NonceBuildAC().nickHash(): ", Err: nickErr}
	}

	counterHash, counterErr := icutl.HashSHA3Data(myCounter)
	if counterErr != nil {
		return nil, &icutl.AcError{Value: -1, Msg: "NonceBuildAC().counterHash(): ", Err: counterErr}
	}

	hdrHash, hdrErr := icutl.HashSHA3Data(msgHdr)
	if hdrErr != nil {
		return nil, &icutl.AcError{Value: -1, Msg: "NonceBuildAC().hdrHash(): ", Err: hdrErr}
	}

	// lets build it now..
	nonceBuild.Write(bobHash)
	nonceBuild.WriteByte(byte(':'))
	nonceBuild.Write(nickHash)
	nonceBuild.WriteByte(byte(':'))
	nonceBuild.Write(counterHash)
	nonceBuild.WriteByte(byte(':'))
	nonceBuild.Write(hdrHash)

	//fmt.Fprintf(os.Stderr, "NonceBuildAC NonceBuild HEX(%d): %s\n", len(nonceBuild.Bytes()), hex.EncodeToString(nonceBuild.Bytes()))

	nonceHash, nonceErr := icutl.HashSHA3Data(nonceBuild.Bytes())
	if nonceErr != nil {
		return nil, &icutl.AcError{Value: -1, Msg: "NonceBuildAC().nonceHash(): ", Err: nonceErr}
	}

	//fmt.Fprintf(os.Stderr, "NonceBuildAC HASH HEX(%d): %s\n", len(nonceHash), hex.EncodeToString(nonceHash))
	return nonceHash, nil
}

func nonceBuildKX(kxChannel, myNick, peerNick, myCounter, msgHdr []byte) (out []byte, err error) {
	nonceBuild := new(bytes.Buffer)

	chanHash, chanErr := icutl.HashSHA3Data(kxChannel)
	if chanErr != nil {
		return nil, &icutl.AcError{Value: -1, Msg: "NonceBuildKX().chanHash(): ", Err: chanErr}
	}

	nickHash, nickErr := icutl.HashSHA3Data(myNick)
	if nickErr != nil {
		return nil, &icutl.AcError{Value: -1, Msg: "NonceBuildKX().nickHash(): ", Err: nickErr}
	}

	peerHash, peerErr := icutl.HashSHA3Data(peerNick)
	if peerErr != nil {
		return nil, &icutl.AcError{Value: -1, Msg: "NonceBuildKX().peerHash(): ", Err: peerErr}
	}

	counterHash, counterErr := icutl.HashSHA3Data(myCounter)
	if counterErr != nil {
		return nil, &icutl.AcError{Value: -1, Msg: "NonceBuildAC().counterHash(): ", Err: counterErr}
	}

	hdrHash, hdrErr := icutl.HashSHA3Data(msgHdr)
	if hdrErr != nil {
		return nil, &icutl.AcError{Value: -1, Msg: "NonceBuildAC().hdrHash(): ", Err: hdrErr}
	}

	// lets build it now..
	nonceBuild.Write(chanHash)
	nonceBuild.WriteByte(byte(':'))
	nonceBuild.Write(nickHash)
	nonceBuild.WriteByte(byte(':'))
	nonceBuild.Write(peerHash)
	nonceBuild.WriteByte(byte(':'))
	nonceBuild.Write(counterHash)
	//binary.Write(nonce_build, binary.LittleEndian, context.nonce)
	nonceBuild.WriteByte(byte(':'))
	nonceBuild.Write(hdrHash)

	nonceHash, nonceErr := icutl.HashSHA3Data(nonceBuild.Bytes())
	if nonceErr != nil {
		return nil, &icutl.AcError{Value: -1, Msg: "NonceBuildAC().nonceHash(): ", Err: nonceErr}
	}

	//icutl.DebugLog.Printf(os.Stderr, "[+] BuildNonceAC(%08x, %s, %s, %s) = %s (%s)\n", inonce, bob, mynick, hex.EncodeToString(myhdr), hex.EncodeToString(noncebyte[:]), hex.EncodeToString(nonce))

	return nonceHash, nil
}

func BuildNonceAC(inonce uint32, bob, mynick, myhdr []byte) (nonce []byte, noncebyte *[24]byte, err error) {
	//	var noncebyte [24]byte
	noncebyte = new([24]byte)

	// current nonce building
	mynonce := Nonce2Byte(inonce)

	// let's build the nonce
	nonce, err = nonceBuildAC(bob, mynick, mynonce, myhdr)
	if err != nil {
		return nil, nil, &icutl.AcError{Value: -1, Msg: "BuildNonceAC().zlib.Write(): ", Err: err}
	}

	// we just need 24 bytes nonce
	copy(noncebyte[:], nonce[:24])

	icutl.DebugLog.Printf("[+] BuildNonceAC(%08x, %s, %s, %s) = %s (%s)\n", inonce, bob, mynick, hex.EncodeToString(myhdr), hex.EncodeToString(noncebyte[:]), hex.EncodeToString(nonce))

	return nonce, noncebyte, nil
}

func BuildNonceKX(inonce uint32, bob, mynick, peernick, myhdr []byte) (nonce []byte, noncebyte *[24]byte, err error) {
	//	var noncebyte [24]byte
	noncebyte = new([24]byte)

	// current nonce building
	mynonce := Nonce2Byte(inonce)

	// let's build the nonce
	nonce, err = nonceBuildKX(bob, mynick, peernick, mynonce, myhdr)
	if err != nil {
		return nil, nil, &icutl.AcError{Value: -1, Msg: "BuildNonceKX().zlib.Write(): ", Err: err}
	}

	// we just need 24 bytes nonce
	copy(noncebyte[:], nonce[:24])

	fmt.Fprintf(os.Stderr, "[+] BuildNonceKX(%08x, %s, %s, %s, %s) = %s (%s)\n", inonce, bob, mynick, peernick, hex.EncodeToString(myhdr), hex.EncodeToString(noncebyte[:]), hex.EncodeToString(nonce))

	return nonce, noncebyte, nil
}

func BuildHeader(in []byte) (bHdr []byte, iHdr uint32, err error) {
	//	fmt.Printf("BuildHeader(\"%s\" (%s))\n", in, hex.EncodeToString(in))
	/* lets build our header */
	bHdr, err = obf.Obfuscate([]byte(in))
	iHdr = binary.LittleEndian.Uint32(bHdr)
	if err != nil {
		return nil, 0, &icutl.AcError{Value: -1, Msg: "BuildHeader(): ", Err: err}
	}
	//	fmt.Printf("BuildHeader(\"%s\"): %s (0x%08x)\n", in, hex.EncodeToString(bHdr), iHdr)
	return bHdr, iHdr, err
}

func CheckHeader(inSlice []byte, in uint32) (rcvHdr []byte, err error) {
	//	fmt.Printf("CheckHeader(\"%s\" (%08x))\n", inSlice, in)
	rcvHdr = make([]byte, 4)
	binary.LittleEndian.PutUint32(rcvHdr, in)

	hdr, err := obf.DeObfuscate(rcvHdr)
	if err != nil {
		//fmt.Fprintf(os.Stderr, "CheckHeader(): cannot deobfuscate\n")
		return nil, &icutl.AcError{Value: -1, Msg: "CheckHeader().Deobfuscate(): ", Err: err}
	}

	if len(hdr) != 2 {
		//fmt.Fprintf(os.Stderr, "CheckHeader(): cannot deobfuscate\n")
		return nil, &icutl.AcError{Value: -2, Msg: "CheckHeader().WrongHeaderSize: ", Err: err}
	}

	if bytes.Compare(hdr, inSlice) != 0 {
		//fmt.Fprintf(os.Stderr, "CheckHeader(): cannot deobfuscate\n")
		// TODO XXX error type and number
		//return nil, acprotoError(-4, "OpenACMessage().Hdr(): ", err)
		return nil, &icutl.AcError{Value: -3, Msg: "OpenACMessage().WrongHeader: ", Err: err}
		//return
	}

	return rcvHdr, nil
}

func IsValidChannelName(input []byte) (ok bool, err error) {
	chanRE := string("^(((![A-Z0-9]{5})|([#+&][^\x00\x07\r\n ,:]+))(:[^\x00\x07\r\n ,:]+)?)$")
	ok, err = regexp.Match(chanRE, input)
	return ok, err
}

//func IsValidNickname(input []byte) (ok bool, err error) {
//    nickRE := string('^([a-zA-Z\[\]\\\`\_\^\{\|\}]{1}[[a-zA-Z0-9\[\]\\\`\_\^\{\|\}\-]{0,8})$')
//    ok, err = regexp.Match(nickRE, input)
//    return ok, err
//}
