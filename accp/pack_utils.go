package accp

import (
	"bytes"
	"code.google.com/p/go.crypto/sha3"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/unix4fun/ac/obf"
	"io"
	"io/ioutil"
	"os"
	"regexp"
	//"time"
)

func HashSHA3Data(input []byte) (out []byte, err error) {
	//sha3hash := sha3.NewKeccak256()
	sha3hash := sha3.New256()
	_, err = sha3hash.Write(input)
	if err != nil {
		//return nil, acprotoError(-1, "HashSHA3Data().Write(): ", err)
		return nil, &protoError{value: -1, msg: "HashSHA3Data().Write(): ", err: err}
	}
	out = sha3hash.Sum(nil)
	return
}

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

func nonceBuildKX(kxChannel, myNick, peerNick, myCounter, msgHdr []byte) (out []byte, err error) {
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

func BuildNonceAC(inonce uint32, bob, mynick, myhdr []byte) (nonce []byte, noncebyte *[24]byte, err error) {
	//	var noncebyte [24]byte
	noncebyte = new([24]byte)

	// current nonce building
	mynonce := Nonce2Byte(inonce)

	// let's build the nonce
	nonce, err = nonceBuildAC(bob, mynick, mynonce, myhdr)
	if err != nil {
		return nil, nil, &protoError{value: -1, msg: "BuildNonceAC().zlib.Write(): ", err: err}
	}

	// we just need 24 bytes nonce
	copy(noncebyte[:], nonce[:24])

	fmt.Fprintf(os.Stderr, "BuildNonceAC(%08x, %s, %s, %s) = %s (%s)\n", inonce, bob, mynick, hex.EncodeToString(myhdr), hex.EncodeToString(noncebyte[:]), hex.EncodeToString(nonce))

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
		return nil, nil, &protoError{value: -1, msg: "BuildNonceKX().zlib.Write(): ", err: err}
	}

	// we just need 24 bytes nonce
	copy(noncebyte[:], nonce[:24])

	fmt.Fprintf(os.Stderr, "BuildNonceKX(%08x, %s, %s, %s, %s) = %s (%s)\n", inonce, bob, mynick, peernick, hex.EncodeToString(myhdr), hex.EncodeToString(noncebyte[:]), hex.EncodeToString(nonce))

	return nonce, noncebyte, nil
}

func B64EncodeData(in []byte) (out []byte) {

	buffer := new(bytes.Buffer)
	encoder := base64.NewEncoder(base64.StdEncoding, buffer)
	encoder.Write(in)
	encoder.Close()

	out = buffer.Bytes()
	return out
}

func B64DecodeData(in []byte) (out []byte, err error) {
	b64str := make([]byte, base64.StdEncoding.DecodedLen(len(in)))

	b64strLen, err := base64.StdEncoding.Decode(b64str, in)
	if err != nil {
		return nil, &protoError{value: -1, msg: "B64DecodeData()||TooSmall: ", err: err}
	}

	b64str = b64str[:b64strLen]
	return b64str, nil
}

//func CompressData(in []byte) (data *bytes.Buffer, err error) {
func CompressData(in []byte) (out []byte, err error) {

	//fmt.Fprintf(os.Stderr, "CompressData(%d bytes)\n", len(in))
	// first let's compress
	data := new(bytes.Buffer)

	zbuf, err := zlib.NewWriterLevel(data, zlib.BestCompression)
	if err != nil {
		return nil, &protoError{value: -1, msg: "CompressData().zlib.NewWriterLevel(): ", err: err}
	}

	n, err := zbuf.Write(in)
	if err != nil || n != len(in) {
		return nil, &protoError{value: -2, msg: "CompressData().zlib.Write(): ", err: err}
	}

	//XXX funny  Flush don't actually flush stuff from zlib into the writer all the time.....
	//zbuf.Flush()
	// XXX let's try...
	zbuf.Close()
	//fmt.Fprintf(os.Stderr, "CompressData(%d B): %d B\n", len(in), data.Len())
	//	zbuf.Close() is defered
	out = data.Bytes()
	//fmt.Printf("OUTPUT: %s\n", hex.EncodeToString(out))
	return out, nil
}

func DecompressData(in []byte) (out []byte, err error) {
	//outbuf := new(bytes.Buffer)

	//fmt.Printf("LEN INPUT : %d\n", len(in))
	//fmt.Printf("INPUT : %s\n", hex.EncodeToString(in))
	zbuf := bytes.NewBuffer(in)
	plain, err := zlib.NewReader(zbuf)
	defer plain.Close()
	if err != nil {
		return nil, &protoError{value: -1, msg: "DecompressData().zlib.NewReader(): ", err: err}
	}

	//_, err = io.Copy(outbuf, plain)
	out, err = ioutil.ReadAll(plain)
	//fmt.Printf("LEN OUTPUT : %d\n", len(out))
	//fmt.Printf("OUTPUT: %s\n", out)
	if err != nil && err != io.EOF {
		return nil, &protoError{value: -2, msg: "DecompressData().ioutil().ReadAll(): ", err: err}
	}

	//out = outbuf.Bytes()
	return out, nil
}

func BuildHeader(in []byte) (bHdr []byte, iHdr uint32, err error) {
	fmt.Printf("BuildHeader(\"%s\" (%s))\n", in, hex.EncodeToString(in))
	/* lets build our header */
	bHdr, err = obf.Obfuscate([]byte(in))
	iHdr = binary.LittleEndian.Uint32(bHdr)
	if err != nil {
		return nil, 0, &protoError{value: -1, msg: "BuildHeader(): ", err: err}
	}
	fmt.Printf("BuildHeader(\"%s\"): %s (0x%08x)\n", in, hex.EncodeToString(bHdr), iHdr)
	return bHdr, iHdr, err
}

func CheckHeader(inSlice []byte, in uint32) (rcvHdr []byte, err error) {
	fmt.Printf("CheckHeader(\"%s\" (%08x))\n", inSlice, in)
	rcvHdr = make([]byte, 4)
	binary.LittleEndian.PutUint32(rcvHdr, in)

	hdr, err := obf.DeObfuscate(rcvHdr)
	if err != nil {
		//fmt.Fprintf(os.Stderr, "CheckHeader(): cannot deobfuscate\n")
		return nil, &protoError{value: -1, msg: "CheckHeader().Deobfuscate(): ", err: err}
	}

	if len(hdr) != 2 {
		//fmt.Fprintf(os.Stderr, "CheckHeader(): cannot deobfuscate\n")
		return nil, &protoError{value: -2, msg: "CheckHeader().WrongHeaderSize: ", err: err}
	}

	if bytes.Compare(hdr, inSlice) != 0 {
		//fmt.Fprintf(os.Stderr, "CheckHeader(): cannot deobfuscate\n")
		// TODO XXX error type and number
		//return nil, acprotoError(-4, "OpenACMessage().Hdr(): ", err)
		return nil, &protoError{value: -3, msg: "OpenACMessage().WrongHeader: ", err: err}
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
