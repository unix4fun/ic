package accp

import (
	"bytes"
	"code.google.com/p/go.crypto/sha3"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"time"
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

func HashSHA3Data(input []byte) (out []byte, err error) {
	//sha3hash := sha3.NewKeccak256()
	sha3hash := sha3.New256()
	_, err = sha3hash.Write(input)
	if err != nil {
		//return nil, acprotoError(-1, "HashSHA3Data().Write(): ", err)
		return nil, &protoError{value: -1, msg: "HashSHA3Data().Write(): ", err: err}
	}
	out = sha3hash.Sum(nil)
	//fmt.Printf("SHA[%d]:%s\n", len(input), hex.EncodeToString(out))
	return
}

func NonceBuildAC(bob, myNick, myCounter, msgHdr []byte) (out []byte, err error) {
	nonceBuild := new(bytes.Buffer)

	bobHash, bobErr := HashSHA3Data(bob)
	if bobErr != nil {
		return nil, &protoError{value: -1, msg: "NonceBuildAC().bobHash(): ", err: bobErr}
	}

	nickHash, nickErr := HashSHA3Data(myNick)
	if nickErr != nil {
		return nil, &protoError{value: -1, msg: "NonceBuildAC().nickHash(): ", err: nickErr}
	}

	counterHash, counterErr := HashSHA3Data(myCounter)
	if counterErr != nil {
		return nil, &protoError{value: -1, msg: "NonceBuildAC().counterHash(): ", err: counterErr}
	}

	hdrHash, hdrErr := HashSHA3Data(msgHdr)
	if hdrErr != nil {
		return nil, &protoError{value: -1, msg: "NonceBuildAC().hdrHash(): ", err: hdrErr}
	}

	// lets build it now..
	nonceBuild.Write(bobHash)
	nonceBuild.WriteByte(byte(':'))
	nonceBuild.Write(nickHash)
	nonceBuild.WriteByte(byte(':'))
	nonceBuild.Write(counterHash)
	nonceBuild.WriteByte(byte(':'))
	nonceBuild.Write(hdrHash)

	fmt.Fprintf(os.Stderr, "NonceBuildAC NonceBuild HEX(%d): %s\n", len(nonceBuild.Bytes()), hex.EncodeToString(nonceBuild.Bytes()))

	nonceHash, nonceErr := HashSHA3Data(nonceBuild.Bytes())
	if nonceErr != nil {
		return nil, &protoError{value: -1, msg: "NonceBuildAC().nonceHash(): ", err: nonceErr}
	}

	fmt.Fprintf(os.Stderr, "NonceBuildAC HASH HEX(%d): %s\n", len(nonceHash), hex.EncodeToString(nonceHash))
	return nonceHash, nil
}

func NonceBuildKX(kxChannel, myNick, peerNick, myCounter, msgHdr []byte) (out []byte, err error) {
	nonceBuild := new(bytes.Buffer)

	chanHash, chanErr := HashSHA3Data(kxChannel)
	if chanErr != nil {
		return nil, &protoError{value: -1, msg: "NonceBuildKX().chanHash(): ", err: chanErr}
	}

	nickHash, nickErr := HashSHA3Data(myNick)
	if nickErr != nil {
		return nil, &protoError{value: -1, msg: "NonceBuildKX().nickHash(): ", err: nickErr}
	}

	peerHash, peerErr := HashSHA3Data(peerNick)
	if peerErr != nil {
		return nil, &protoError{value: -1, msg: "NonceBuildKX().peerHash(): ", err: peerErr}
	}

	counterHash, counterErr := HashSHA3Data(myCounter)
	if counterErr != nil {
		return nil, &protoError{value: -1, msg: "NonceBuildAC().counterHash(): ", err: counterErr}
	}

	hdrHash, hdrErr := HashSHA3Data(msgHdr)
	if hdrErr != nil {
		return nil, &protoError{value: -1, msg: "NonceBuildAC().hdrHash(): ", err: hdrErr}
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

	nonceHash, nonceErr := HashSHA3Data(nonceBuild.Bytes())
	if nonceErr != nil {
		return nil, &protoError{value: -1, msg: "NonceBuildAC().nonceHash(): ", err: nonceErr}
	}

	return nonceHash, nil
}
