// +build go1.4
package accp

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"github.com/golang/protobuf/proto" // protobuf is now here.
	"github.com/unix4fun/ac/obf"
	"golang.org/x/crypto/nacl/secretbox"
	"io"
	"os"
)

func packMessageAC(hdr, nonce *uint32, blob *[]byte) (out []byte, err error) {

	acOut := &ACPackedMessage{}
	acOut.Header = hdr
	acOut.Nonce = proto.Uint32(*nonce)
	acOut.Ciphertext = *blob
	//acOut.Options = proto.Uint32(10034)

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

func unpackMessageAC(in []byte) (mNonce uint32, myHdr, ciphertext []byte, err error) {

	acIn := &ACPackedMessage{}
	err = proto.Unmarshal(in, acIn)
	if err != nil {
		return 0, nil, nil, err
	}

	myHdr, err = CheckHeader([]byte(msgHdrAC), acIn.GetHeader())
	if err != nil {
		return 0, nil, nil, err
	}

	//XXX TODO more meaningful updates from here...
	//fmt.Printf("Nonce: %d(%08x)\n", acIn.GetNonce(), acIn.GetNonce())
	return acIn.GetNonce(), myHdr, acIn.GetCiphertext(), nil
}

// A very pragmatic approach to protobuf encoding it's roughly true for most cases.
func PredictLenNACL(input []byte) (outlen int) {
	zipped, err := CompressData(input)
	if err != nil {
		return 0
	}
	sboxLen := len(zipped)        // zipped data
	sboxLen += secretbox.Overhead // NACL hash appended
	sboxLen += 3                  // 1 byte pb header value type + 2 bytes size  for the bytes part in PB message
	sboxLen += 6                  // 1 byte pb header + 1 byte size + 4 bytes data for AC header in PB message
	sboxLen += 7                  // 1 byte pb header value type + 2 byte size + 4 bytes nonce
	sboxLen += 2                  // 1 byte pb header value type + 1 byte size
	outlen = base64.StdEncoding.EncodedLen(sboxLen)
	//outlen += 14
	fmt.Fprintf(os.Stderr, "PredictLenNACL(%d): %d\n", len(input), outlen)
	return outlen
}

//
// AC Message OLD Format:
// BASE64( 'AC' || 'NONCE_VALUE' || SECRETBOX( KEY, NONCE_AUTH, ZLIB( MSG ) )
//
// AC Message NEW Format:
// BASE64( 'AC' || 'OPTIONS' || 'NONCE_VALUE' || SECRETBOX( KEY, NONCE_AUTH, ZLIB( MSG ) )
//
// Nonce AUTH OLD Format:
// SHA3( 'CHANNEL' || ':' || 'SRC_NICK' || ':' || 'NONCE_VALUE' || ':' || 'HDR_RAW' )
//
// Nonce AUTH NEW Format:
// SHA3( SHA3('CHANNEL') || ':' || SHA3('SRC_NICK') || ':' || SHA3('NONCE_VALUE') || ':' || 'HDR_RAW=AC||OPTIONS||NONCE_VALUE' )
//
// OPTIONS:
// 0x01 = NaCL secretbox
// 0x02 = AES-GCM
// 0x?0 = PROTO VERSION [ 0 - 15 ]
//
//
func CreateACMessageNACL(context *SecKey, rnd, msg, myNick []byte) (out []byte, err error) {
	//var noncebyte [24]byte

	/* lets build our header */
	myHdr, intHdr, err := BuildHeader([]byte(msgHdrAC))
	if err != nil {
		return nil, &protoError{value: -1, msg: "CreateACMessageNACL().BuildHeader(): ", err: err}
	}

	// first let's compress
	myBody, err := CompressData(msg)
	if err != nil {
		return nil, &protoError{value: -2, msg: "CreateACMessageNACL().CompressData(): ", err: err}
	}

	//BuildNonceAC(inonce uint32, bob, mynick, myhdr []byte) (nonce []byte, noncebyte *[24]byte, err error)
	_, noncebyte, err := BuildNonceAC(context.nonce, context.bob, myNick, myHdr)

	// OPEN the key
	// XXX new to check rnd and context.key are the same size
	for j := 0; j < len(rnd); j++ {
		context.key[j] = context.key[j] ^ rnd[j]
	}

	// encrypt
	myCipher := secretbox.Seal(nil, myBody, noncebyte, context.key)

	// close the key
	for j := 0; j < len(rnd); j++ {
		context.key[j] = context.key[j] ^ rnd[j]
	}

	// XXX error checking
	out, err = packMessageAC(&intHdr, &context.nonce, &myCipher)

	//fmt.Fprintf(os.Stderr, "NACL PB == AC MSG OUT[%d]: %s\n", len(out), out)
	context.nonce++

	return out, nil
}

func OpenACMessageNACL(context *SecKey, rnd, cmsg, peerNick, myNick []byte) (out []byte, err error) {
	fmt.Fprintf(os.Stderr, "OpenACMessageNACL()\n")
	b64, err := B64DecodeData(cmsg)
	if err != nil {
		return nil, &protoError{value: -1, msg: "OpenACMessageNACL(): ", err: err}
	}

	cnonce, myHdr, ciphertext, err := unpackMessageAC(b64)
	if err != nil {
		return nil, &protoError{value: -2, msg: "OpenACMessageNACL(): ", err: err}
	}

	// XXX this is to handle private message instead of channel communication
	// as the destination are assymetrical eau's dst is frl and frl's dst is eau
	//
	ac_bob := context.bob
	ok_bob, _ := IsValidChannelName(ac_bob)
	fmt.Fprintf(os.Stderr, "[+] OpenACMessage: is %s a valid channel: %t\n", ac_bob, ok_bob)
	if ok_bob == false && len(myNick) > 0 {
		ac_bob = myNick
	}

	/* let's build the nonce */
	//BuildNonceAC(inonce uint32, bob, mynick, myhdr []byte) (nonce []byte, noncebyte *[24]byte, err error)
	_, noncebyte, err := BuildNonceAC(cnonce, ac_bob, peerNick, myHdr)

	// OPEN the key
	// XXX new to check rnd and context.key are the same size
	for j := 0; j < len(rnd); j++ {
		context.key[j] = context.key[j] ^ rnd[j]
	}

	packed, ok := secretbox.Open(nil, ciphertext, noncebyte, context.key)

	// Close the key
	for j := 0; j < len(rnd); j++ {
		context.key[j] = context.key[j] ^ rnd[j]
	}

	if ok == false {
		//return nil, acprotoError(1, "OpenACMessage().SecretOpen(): false ", nil)
		return nil, &protoError{value: -3, msg: "OpenACMessageNACL().SecretOpen(): ", err: nil}
	}

	out, err = DecompressData(packed)
	if err != nil {
		return nil, &protoError{value: -3, msg: "OpenACMessageNACL().DecompressData(): ", err: err}
	}

	//nonceval = acIn.GetNonce()
	// update the nonce value
	if cnonce > context.nonce {
		context.nonce = cnonce + 1
	} else {
		context.nonce++
	}
	return out, nil
	//return nil, nil
}

func CreateACMessage(context *SecKey, rnd, msg, myNick []byte) (out []byte, err error) {
	var noncebyte [24]byte
	hdr, err := obf.Obfuscate([]byte(msgHdrAC))
	if err != nil {
		return nil, &protoError{value: -1, msg: "CreateACMessage().Obfuscate(): ", err: err}
	}

	// first let's compress
	body := new(bytes.Buffer)
	zbuf, err := zlib.NewWriterLevel(body, zlib.BestCompression)
	if err != nil {
		return nil, &protoError{value: -2, msg: "CreateACMessage().zlib.NewWriterLevel(): ", err: err}
	}

	_, err = zbuf.Write(msg)
	if err != nil {
		return nil, &protoError{value: -3, msg: "CreateACMessage().zlib.Write(): ", err: err}
	}
	zbuf.Close()

	// XXX this is to handle private message instead of channel communication
	// as the destination are assymetrical eau's dst is frl and frl's dst is eau
	// I'm adding complexity where i need none, i just need an additionnal
	// parameter on OpenACMessage.. if it's a channel then i use that parameter
	// that's it.
	//
	//ac_bob := context.bob
	//ok_bob, _ := IsValidChannelName(ac_bob)
	//fmt.Printf("[+] CreateACMessage: is %s a valid channel: %t\n", ac_bob, ok_bob)
	//if ok_bob == false {
	//    // private channel building!
	//    acb_build := new(bytes.Buffer)
	//    acb_build.Write([]byte(myNick))
	//    acb_build.WriteByte(byte('='))
	//    acb_build.Write([]byte(ac_bob))
	//    ac_bob = acb_build.Bytes()
	//    fmt.Printf("[+] CreateACMessage: not a channel, private conversation let's use this: %s\n", ac_bob)
	//}

	// nonce building!
	// XXX TODO: this require hash() of all values..
	nonce_build := new(bytes.Buffer)
	nonce_build.Write(context.bob)
	// XXX this solution is sub optimal... may be adding an argument is better...
	//nonce_build.Write(ac_bob)
	nonce_build.WriteByte(byte(':'))
	nonce_build.Write(myNick)
	nonce_build.WriteByte(byte(':'))
	binary.Write(nonce_build, binary.LittleEndian, context.nonce)
	nonce_build.WriteByte(byte(':'))
	nonce_build.Write(hdr)
	//fmt.Fprintf(os.Stderr, "ENCODE NONCE HEX: %s (%s)\n", hex.EncodeToString(nonce_build.Bytes()), nonce_build.Bytes())

	nonce_sha, err := HashSHA3Data(nonce_build.Bytes())
	if err != nil {
		//return nil, acprotoError(-4, "CreateACMessage().HashSHA3Data(): ", err)
		return nil, &protoError{value: -4, msg: "CreateACMessage().HashSHA3Data(): ", err: err}
	}
	copy(noncebyte[:], nonce_sha[:24])
	//fmt.Printf("ENCODE SHA HEX(%d): %s\n", len(body.Bytes()), hex.EncodeToString(nonce_sha))

	// OPEN the key
	// XXX new to check rnd and context.key are the same size
	for j := 0; j < len(rnd); j++ {
		context.key[j] = context.key[j] ^ rnd[j]
	}
	// encrypt
	cipher := secretbox.Seal(nil, body.Bytes(), &noncebyte, context.key)

	// close the key
	for j := 0; j < len(rnd); j++ {
		context.key[j] = context.key[j] ^ rnd[j]
	}

	buffer := new(bytes.Buffer)
	encoder := base64.NewEncoder(base64.StdEncoding, buffer)
	encoder.Write(hdr)
	binary.Write(encoder, binary.LittleEndian, context.nonce)
	encoder.Write(cipher)
	encoder.Close()

	out = buffer.Bytes()
	//fmt.Fprintf(os.Stderr, "AC MSG OUT[%d]: %s\n", len(out), out)
	context.nonce++
	return
}

func OpenACMessage(context *SecKey, rnd, cmsg, peerNick, myNick []byte) (out []byte, err error) {
	var noncebyte [24]byte
	var nonceval uint32

	fmt.Fprintf(os.Stderr, "OpenACMessage()\n")
	b64str := make([]byte, base64.StdEncoding.DecodedLen(len(cmsg)))

	b64str_len, err := base64.StdEncoding.Decode(b64str, cmsg)
	if err != nil || b64str_len <= 8 {
		//fmt.Fprintf(os.Stderr, "DECODE FUCK || Too Small!\n")
		//return nil, acprotoError(-1, "OpenACMessage().B64Decode()||TooSmall: ", err)
		return nil, &protoError{value: -1, msg: "OpenACMessage().B64Decode()||TooSmall: ", err: err}
		//return
	}

	hdr, err := obf.DeObfuscate(b64str[:4])
	if err != nil {
		fmt.Fprintf(os.Stderr, "CA FOIRE!!!!\n")
		//return nil, acprotoError(-2, "OpenACMessage().Deobfuscate(): ", err)
		return nil, &protoError{value: -2, msg: "OpenACMessage().Deobfuscate(): ", err: err}
		//panic(err)
		//return
	}

	if len(hdr) != 2 {
		fmt.Fprintf(os.Stderr, "WRONG HEADER")
		// TODO XXX error type and number
		//return nil, acprotoError(-3, "OpenACMessage().Hdr(): ", err)
		return nil, &protoError{value: -3, msg: "OpenACMessage().Hdr(): ", err: err}
		//return
	}

	if bytes.Compare(hdr, []byte(msgHdrAC)) != 0 {
		fmt.Fprintf(os.Stderr, "WRONG HEADER 2")
		// TODO XXX error type and number
		//return nil, acprotoError(-4, "OpenACMessage().Hdr(): ", err)
		return nil, &protoError{value: -4, msg: "OpenACMessage().Hdr(): ", err: err}
		//return
	}

	// XXX this is to handle private message instead of channel communication
	// as the destination are assymetrical eau's dst is frl and frl's dst is eau
	//
	ac_bob := context.bob
	ok_bob, _ := IsValidChannelName(ac_bob)
	fmt.Fprintf(os.Stderr, "[+] OpenACMessage: is %s a valid channel: %t\n", ac_bob, ok_bob)
	if ok_bob == false && len(myNick) > 0 {
		//    // private channel building!
		//    acb_build := new(bytes.Buffer)
		//    acb_build.Write([]byte(ac_bob))
		//    acb_build.WriteByte(byte('='))
		//    acb_build.Write([]byte(peerNick))
		//    ac_bob = acb_build.Bytes()
		//    fmt.Printf("[+] OpenACMessage: not a channel, private conversation let's use this: %s\n", ac_bob)
		ac_bob = myNick
	}

	nonce_get := bytes.NewReader(b64str[4:8])
	err = binary.Read(nonce_get, binary.LittleEndian, &nonceval)
	if err != nil {
		//return nil, acprotoError(-8, "OpenACMessage().nonce_get(): ", err)
		return nil, &protoError{value: -5, msg: "OpenACMessage().nonce_get(): ", err: err}
		//    //log.Fatal(err)
		//    //return
	}

	nonce_buf := b64str[4:8]
	nonce_build := new(bytes.Buffer)
	//nonce_build.Write(context.bob)
	// XXX this solution is sub optimal... may be adding an argument is better...
	nonce_build.Write(ac_bob)
	nonce_build.WriteByte(byte(':'))
	nonce_build.Write(peerNick)
	nonce_build.WriteByte(byte(':'))
	nonce_build.Write(nonce_buf)
	nonce_build.WriteByte(byte(':'))
	nonce_build.Write(b64str[:4])
	//nonce_buf := bytes.NewReader(b64str[4:8])
	//binary.Read(nonce_buf, binary.LittleEndian, &in)
	//fmt.Fprintf(os.Stderr, "DECODE NONCE HEX(%d): %s(%s)\n", len(nonce_build.Bytes()), hex.EncodeToString(nonce_build.Bytes()), nonce_build.Bytes())

	nonce_sha, err := HashSHA3Data(nonce_build.Bytes())
	if err != nil {
		//return nil, acprotoError(-4, "OpenACMessage().HashSHA3Data(): ", err)
		return nil, &protoError{value: -6, msg: "OpenACMessage().HashSHA3Data(): ", err: err}
		//return
	}
	copy(noncebyte[:], nonce_sha[:24])
	//fmt.Printf("DECODE SHA HEX: %s\n", hex.EncodeToString(noncebyte[:]))

	// OPEN the key
	// XXX new to check rnd and context.key are the same size
	for j := 0; j < len(rnd); j++ {
		context.key[j] = context.key[j] ^ rnd[j]
	}

	//plain = make([]byte, len(b64str[8:])-secretbox.Overhead)
	//bounce := b64str[8:b64str_len]
	//fmt.Printf("LAST BYTE: %02x\n", bounce[len(bounce)-1:len(bounce)])
	//bounce = bounce[:len(bounce)-1]
	//fmt.Printf("B64 LEN %d CIPHER TEXT : %d\n", len(b64str[4:8]), len(bounce))
	//    fmt.Printf("NONCE LEN: %d\n", len(noncebyte))
	//    fmt.Printf("KEY LEN: %d\n", len(context.key))
	packed, ok := secretbox.Open(nil, b64str[8:b64str_len], &noncebyte, context.key)
	//    fmt.Printf("C EST OK?!?!?\n")
	//    fmt.Println(ok)
	// Close the key
	for j := 0; j < len(rnd); j++ {
		context.key[j] = context.key[j] ^ rnd[j]
	}

	if ok == false {
		//return nil, acprotoError(1, "OpenACMessage().SecretOpen(): false ", nil)
		return nil, &protoError{value: -7, msg: "OpenACMessage().SecretOpen(): ", err: nil}
	}
	//fmt.Fprintf(os.Stderr, "DECODED UNSEALED: %s\n", packed)
	//fmt.Printf("DECODED UNSEALED: %s\n", ret)

	zbuf := bytes.NewBuffer(packed)
	plain, err := zlib.NewReader(zbuf)
	if err != nil {

		//        fmt.Println(err)
		//return nil, acprotoError(-5, "OpenACMessage().zlib.NewReader(): ", err)
		return nil, &protoError{value: -8, msg: "OpenACMessage().zlib.NewReader(): ", err: err}
		//return
	}

	//    fmt.Println(plain)
	b := new(bytes.Buffer)
	_, err = io.Copy(b, plain)
	if err != nil {
		//return nil, acprotoError(-6, "OpenACMessage().io.Copy(): ", err)
		return nil, &protoError{value: -9, msg: "OpenACMessage().io.Copy(): ", err: err}
		//panic(err)
	}
	//fmt.Fprintf(os.Stderr, "DECODED UNSEALED: %s\n", b.Bytes())
	plain.Close()
	out = b.Bytes()

	// update the nonce value
	if nonceval > context.nonce {
		context.nonce = nonceval + 1
	} else {
		context.nonce++
	}
	return out, nil
	//return
}
