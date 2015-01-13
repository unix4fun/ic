package accp

import (
	"bytes"
	"code.google.com/p/go.crypto/nacl/box"
	"code.google.com/p/goprotobuf/proto"
	"compress/zlib"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/unix4fun/ac/obf"
	"io"
	"os"
)

func packMessageKX(hdr, nonce *uint32, dst, blob []byte) (out []byte, err error) {

	acOut := &ACPackedMessage{}
	acOut.Header = hdr
	acOut.Nonce = proto.Uint32(*nonce)
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

func CreateKXMessageNACL(context *SecKey, rnd []byte, peerPubkey, myPrivkey *[32]byte, channel, myNick, peerNick []byte) (out []byte, err error) {

	/* lets build our header */
	myHdr, intHdr, err := BuildHeader([]byte(msgHdrKX))
	if err != nil {
		return nil, &protoError{value: -1, msg: "CreateKXMessageNACL().BuildHeader(): ", err: err}
	}

	// Open the key
	for j := 0; j < len(rnd); j++ {
		context.key[j] = context.key[j] ^ rnd[j]
	}

	//fmt.Fprintf(os.Stderr, "CREATE KX KEY: %s\n", hex.EncodeToString(context.key[:]))
	// first let's compress
	myBody, err := CompressData(context.key[:])
	if err != nil {
		return nil, &protoError{value: -2, msg: "CreateKXMessageNACL().CompressData(): ", err: err}
	}

	// Close the key
	for j := 0; j < len(rnd); j++ {
		context.key[j] = context.key[j] ^ rnd[j]
	}

	//fmt.Fprintf(os.Stderr, "channel: %s context.bob: %s\n", channel, context.bob)

	kx_channel := IsChannelOrPriv(channel, myNick, peerNick)
	// XXX i can probably use context.bob instead of a specific channel specification...
	//BuildNonceAC(inonce uint32, bob, mynick, myhdr []byte) (nonce []byte, noncebyte *[24]byte, err error)
	_, noncebyte, err := BuildNonceKX(context.nonce, kx_channel, myNick, peerNick, myHdr)

	//fmt.Fprintf(os.Stderr, "peerpk : %p myprivkey: %p\n", peerPubkey, myPrivkey)
	// XXX TODO: need serious cleanup and error checking!!
	//fmt.Fprintf(os.Stderr, "body.Bytes(): %p, noncebyte: %p, peerPub: %p myPriv: %p\n", myBody, &noncebyte, peerPubkey, myPrivkey)
	cipherKex := box.Seal(nil, myBody, noncebyte, peerPubkey, myPrivkey)

	//func packMessageKX(hdr, nonce *uint32, dst, blob *[]byte) (out []byte, err error) {
	out, err = packMessageKX(&intHdr, &context.nonce, peerNick, cipherKex)
	if err != nil {
		return nil, &protoError{value: -3, msg: "CreateKXMessageNACL().packMessageKX(): ", err: err}
	}

	context.nonce++
	return
}

func OpenKXMessageNACL(peerPubkey, myPrivkey *[32]byte, cmsg, channel, myNick, peerNick []byte) (context *SecKey, SecRnd []byte, err error) {
	// check that we are indeed
	if peerPubkey == nil || myPrivkey == nil {
		//return nil, acprotoError(-1, "OpenKXMessage().invalidPubPrivKeys(): ", err)
		return nil, nil, &protoError{value: -1, msg: "OpenKXMessageNACL().invalidPubPrivKeys(): ", err: err}
	}

	b64, err := B64DecodeData(cmsg)
	if err != nil {
		return nil, nil, &protoError{value: -2, msg: "OpenKXMessageNACL(): ", err: err}
	}

	cnonce, myHdr, ciphertext, err := unpackMessageKX(b64)
	if err != nil {
		return nil, nil, &protoError{value: -3, msg: "OpenKXMessageNACL(): ", err: err}
	}

	// XXX TODO: exact opposite of the one in CreateKXMessage
	kx_channel := IsChannelOrPriv(channel, peerNick, myNick)

	// XXX TODO: we should add the header like <ackx:peerNick> to avoid replay from
	// other nickname on the channel... nonce building!
	_, noncebyte, err := BuildNonceKX(cnonce, kx_channel, peerNick, myNick, myHdr)
	if err != nil {
		return nil, nil, &protoError{value: -4, msg: "OpenKXMessageNACL(): ", err: err}
	}

	packed, ok := box.Open(nil, ciphertext, noncebyte, peerPubkey, myPrivkey)
	if ok == false {
		return nil, nil, &protoError{value: -5, msg: "OpenKXMessageNACL().BoxOpen(): ", err: nil}
	}

	out, err := DecompressData(packed)
	if err != nil {
		return nil, nil, &protoError{value: -6, msg: "OpenKXMessageNACL(): ", err: err}
	}

	//fmt.Fprintf(os.Stderr, "OPEN KX KEY: %s\n", hex.EncodeToString(out))
	// XXX TODO are we at the end of the nonce value..
	context, err = CreateACContext(channel, cnonce+1)
	if err != nil {
		return nil, nil, &protoError{value: -7, msg: "OpenKXMessage().CreateACContext(): ", err: err}
	}

	// XXX TODO
	// get RANDOMNESS bytes, return the random bytes
	newRnd := make([]byte, len(context.key))
	_, err = rand.Read(newRnd)
	if err != nil {
		return nil, nil, &protoError{value: -8, msg: "OpenKXMessage() no randomness to protect the key in memory: ", err: err}
	}

	// XXX TODO: check the extracted buffer size... to sure we're not copying
	// too much into a restricted buffer...
	copy(context.key[:], out)

	// Xor the key now..
	for j := 0; j < len(newRnd); j++ {
		context.key[j] = context.key[j] ^ newRnd[j]
	}

	return context, newRnd, nil
}

//
// KX (Key eXchange) Message Format:
// BASE64( 'KX' || 'NONCE_VALUE' || BOX( PEER_PUBKEY, ME_PRIVKEY, NONCE_AUTH, ZLIB( SECRET ) )
//
// Nonce AUTH Format:
// SHA3( 'CHANNEL' || ':' || 'MY_NICK' || ':' || 'PEER_NICK' || ':' || 'NONCE_VALUE' || ':' || 'HDR_RAW' )
//

func CreateKXMessage(context *SecKey, rnd []byte, peerPubkey, myPrivkey *[32]byte, channel, myNick, peerNick []byte) (out []byte, err error) {
	var noncebyte [24]byte

	hdr, err := obf.Obfuscate([]byte(msgHdrKX))
	if err != nil {
		//return nil, acprotoError(-1, "CreateKXMessage().Hdr(): ", err)
		return nil, &protoError{value: -1, msg: "CreateKXMessage().Hdr(): ", err: err}
	}

	body := new(bytes.Buffer)

	//fmt.Printf("INIT LEN: %d\n", len(body.Bytes()))
	// first let's compress
	//fmt.Printf("MSG(%d): %s\n", len(msg), msg)
	zbuf, err := zlib.NewWriterLevel(body, zlib.BestCompression)
	if err != nil {
		//return nil, acprotoError(-2, "CreateKXMessage().zlib.NewWriterLevel(): ", err)
		return nil, &protoError{value: -2, msg: "CreateKXMessage().zlib.NewWriterLevel(): ", err: err}
		//panic(err)
	}

	// Open the key
	for j := 0; j < len(rnd); j++ {
		context.key[j] = context.key[j] ^ rnd[j]
	}

	_, err = zbuf.Write(context.key[:])
	if err != nil {
		//return nil, acprotoError(-3, "CreateKXMessage().zlib.Write(): ", err)
		return nil, &protoError{value: -3, msg: "CreateKXMessage().zlib.Write(): ", err: err}
	}
	zbuf.Close()
	//fmt.Printf("Compressed: %d bytes -> %d bytes\n", n, len(body.Bytes()))

	// Close the key
	for j := 0; j < len(rnd); j++ {
		context.key[j] = context.key[j] ^ rnd[j]
	}

	// XXX this handle the fact that it is a channel or a private message, it is
	// very IRC specific as such, think again before modifying the format, you
	// might break the crypto too...
	kx_channel := channel
	ok_channel, _ := IsValidChannelName(kx_channel)
	fmt.Fprintf(os.Stderr, "[+] CreateKXMessage: is %s a valid channel: %t\n", kx_channel, ok_channel)
	if ok_channel == false {
		//kx_channel := channel
		// nonce building!
		kxc_build := new(bytes.Buffer)
		kxc_build.Write([]byte(myNick))
		kxc_build.WriteByte(byte('='))
		kxc_build.Write([]byte(peerNick))
		kx_channel = kxc_build.Bytes()
		fmt.Fprintf(os.Stderr, "[+] CreateKXMessage: not a channel, private conversation let's use this: %s\n", kx_channel)
	}

	// nonce building!
	nonce_build := new(bytes.Buffer)
	nonce_build.Write(kx_channel)
	nonce_build.WriteByte(byte(':'))
	nonce_build.Write(myNick)
	nonce_build.WriteByte(byte(':'))
	nonce_build.Write(peerNick)
	nonce_build.WriteByte(byte(':'))
	// XXX TODO: need to clean up and do some more sanity checks...
	binary.Write(nonce_build, binary.LittleEndian, context.nonce)
	nonce_build.WriteByte(byte(':'))
	nonce_build.Write(hdr)
	//fmt.Printf("ENCODE KEX NONCE HEX: %s\n", hex.EncodeToString(nonce_build.Bytes()))

	nonce_sha, err := HashSHA3Data(nonce_build.Bytes())
	if err != nil {
		//return nil, acprotoError(-4, "CreateKXMessage().HashSHA3Data(): ", err)
		return nil, &protoError{value: -4, msg: "CreateKXMessage().HashSHA3Data(): ", err: err}
	}
	copy(noncebyte[:], nonce_sha[:24])
	//fmt.Printf("ENCODE KEX NONCE SHA: %s\n", hex.EncodeToString(nonce_sha))

	fmt.Fprintf(os.Stderr, "peerpk : %p myprivkey: %p\n", peerPubkey, myPrivkey)
	// XXX TODO: need serious cleanup and error checking!!
	fmt.Fprintf(os.Stderr, "body.Bytes(): %p, noncebyte: %p, peerPub: %p myPriv: %p\n", body.Bytes(), &noncebyte, peerPubkey, myPrivkey)
	cipherKex := box.Seal(nil, body.Bytes(), &noncebyte, peerPubkey, myPrivkey)

	buffer := new(bytes.Buffer)
	//buffer.Write(hdr)
	////fmt.Printf("FINAL MESSAGE (%d)\n", len(buffer.Bytes()))
	//binary.Write(buffer, binary.LittleEndian, context.nonce)
	////fmt.Printf("FINAL MESSAGE (%d)\n", len(buffer.Bytes()))
	//buffer.Write(cipher)
	//fmt.Printf("FINAL MESSAGE (%d)\n", len(buffer.Bytes()))

	//out = make([]byte, base64.StdEncoding.EncodedLen(len(buffer.Bytes())) )
	//base64.StdEncoding.Encode(out, buffer.Bytes())

	encoder := base64.NewEncoder(base64.StdEncoding, buffer)
	_, err = encoder.Write(hdr)
	if err != nil {
		//return nil, acprotoError(-5, "CreateKXMessage().B64Encode(): ", err)
		return nil, &protoError{value: -5, msg: "CreateKXMessage().B64Encode(): ", err: err}
	}
	binary.Write(encoder, binary.LittleEndian, context.nonce)
	_, err = encoder.Write(cipherKex)
	if err != nil {
		//return nil, acprotoError(-6, "CreateKXMessage().B64Encode(): ", err)
		return nil, &protoError{value: -6, msg: "CreateKXMessage().B64Encode(): ", err: err}
	}
	encoder.Close()

	out = buffer.Bytes()
	//fmt.Printf("AC MSG OUT[%d]: %s\n", len(out), out)

	context.nonce++
	return
}

func OpenKXMessage(peerPubkey, myPrivkey *[32]byte, cmsg, channel, myNick, peerNick []byte) (context *SecKey, SecRnd []byte, err error) {
	var noncebyte [24]byte
	var nonceval uint32

	// check that we are indeed
	if peerPubkey == nil || myPrivkey == nil {
		//return nil, acprotoError(-1, "OpenKXMessage().invalidPubPrivKeys(): ", err)
		return nil, nil, &protoError{value: -1, msg: "OpenKXMessage().invalidPubPrivKeys(): ", err: err}
	}

	b64str := make([]byte, base64.StdEncoding.DecodedLen(len(cmsg)))
	b64str_len, err := base64.StdEncoding.Decode(b64str, cmsg)
	if err != nil || b64str_len <= 8 {
		//return nil, acprotoError(-1, "OpenKXMessage().B64Decode()||TooSmall: ", err)
		return nil, nil, &protoError{value: -2, msg: "OpenKXMessage().B64Decode()||Too small: ", err: err}
		//panic(err)
		//return
	}

	hdr, err := obf.DeObfuscate(b64str[:4])
	if err != nil {
		//return nil, acprotoError(-2, "OpenKXMessage().Hdr(): ", err)
		return nil, nil, &protoError{value: -3, msg: "OpenKXMessage().Hdr(): ", err: err}
		//panic(err)
		//return
	}

	if len(hdr) != 2 {
		//fmt.Printf("WRONG HEADER")
		//return nil, acprotoError(-3, "OpenKXMessage().Hdr(): ", err)
		return nil, nil, &protoError{value: -4, msg: "OpenKXMessage().Hdr(): ", err: err}
		//return
	}

	if bytes.Compare(hdr, []byte(msgHdrKX)) != 0 {
		//fmt.Printf("WRONG HEADER")
		//return nil, acprotoError(-4, "OpenKXMessage().Hdr(): ", err)
		return nil, nil, &protoError{value: -5, msg: "OpenKXMessage().Hdr(): ", err: err}
		//return
	}

	kx_channel := channel
	ok_channel, _ := IsValidChannelName(kx_channel)
	fmt.Fprintf(os.Stderr, "[+] OpenKXMessage: is %s a valid channel: %t\n", channel, ok_channel)
	if ok_channel == false {
		// private channel building!
		kxc_build := new(bytes.Buffer)
		kxc_build.Write([]byte(peerNick))
		kxc_build.WriteByte(byte('='))
		kxc_build.Write([]byte(myNick))
		kx_channel = kxc_build.Bytes()
		fmt.Fprintf(os.Stderr, "[+] OpenKXMessage: not a channel, private conversation let's use this: %s\n", kx_channel)
	}

	//fmt.Printf("Decoded LEN: %d\n", b64str_len)
	//   fmt.Printf("Decoded HDR: %s\n", hdr)
	// XXX TODO: we should add the header like <ackx:peerNick> to avoid replay from
	// other nickname on the channel...
	// nonce building!
	nonce_buf := b64str[4:8]
	nonce_build := new(bytes.Buffer)
	nonce_build.Write(kx_channel)
	nonce_build.WriteByte(byte(':'))
	nonce_build.Write(peerNick)
	nonce_build.WriteByte(byte(':'))
	nonce_build.Write(myNick)
	nonce_build.WriteByte(byte(':'))
	nonce_build.Write(nonce_buf)
	nonce_build.WriteByte(byte(':'))
	nonce_build.Write(b64str[:4])

	//fmt.Printf("DECODE KEX NONCE HEX: %s\n", hex.EncodeToString(nonce_build.Bytes()))
	nonce_sha, err := HashSHA3Data(nonce_build.Bytes())
	if err != nil {
		//return nil, acprotoError(-5, "OpenKXMessage().HashSHA3Data(): ", err)
		return nil, nil, &protoError{value: -6, msg: "OpenKXMessage().HashSHA3Data(): ", err: err}
	}
	copy(noncebyte[:], nonce_sha[:24])
	//fmt.Printf("DECODE KEX NONCE SHA: %s\n", hex.EncodeToString(nonce_sha))

	//cipherKex := box.Seal(nil, body.Bytes(), &noncebyte, peerPubkey, myPrivkey)
	//nonce_buf := bytes.NewReader(b64str[4:8])
	//binary.Read(nonce_buf, binary.LittleEndian, &in)
	//   fmt.Printf("DECODE NONCE HEX: %s\n", hex.EncodeToString(nonce_build.Bytes()))

	//nonce_sha, err := HashSHA3Data(nonce_build.Bytes())
	//copy(noncebyte[:], nonce_sha[:24])

	packed, ok := box.Open(nil, b64str[8:b64str_len], &noncebyte, peerPubkey, myPrivkey)
	//fmt.Println(ok)
	if ok == false {
		//fmt.Printf("ON RETURN ON PEUT PAS OPEN LE SEAL\n")
		//return nil, acprotoError(-6, "OpenKXMessage().BoxOpen(): ", nil)
		return nil, nil, &protoError{value: -7, msg: "OpenKXMessage().BoxOpen(): ", err: nil}
		//return
	}
	//    fmt.Printf("DECODE SHA HEX: %s\n", hex.EncodeToString(noncebyte[:]))
	zbuf := bytes.NewBuffer(packed)
	plain, err := zlib.NewReader(zbuf)
	defer plain.Close()
	if err != nil {
		//return nil, acprotoError(-7, "OpenKXMessage().zlib.NewReader(): ", err)
		return nil, nil, &protoError{value: -8, msg: "OpenKXMessage().zlib.NewReader(): ", err: err}
		//log.Fatal(err)
		//return
	}

	// XXX some checks are necessary

	nonceBuf := bytes.NewReader(b64str[4:8])
	err = binary.Read(nonceBuf, binary.LittleEndian, &nonceval)
	if err != nil {
		//return nil, acprotoError(-8, "OpenKXMessage().Hdr(): ", err)
		return nil, nil, &protoError{value: -9, msg: "OpenKXMessage().Hdr(): ", err: err}
		//log.Fatal(err)
		//return
	}
	// create the nonce uint32 value from the buffer of the received message
	// XXX TODO are we at the end of the nonce value..
	context, err = CreateACContext(channel, nonceval+1)
	if err != nil {
		//return nil, acprotoError(-9, "OpenKXMessage().CreateACContext(): ", err)
		return nil, nil, &protoError{value: -10, msg: "OpenKXMessage().CreateACContext(): ", err: err}
		//return
	}

	b := new(bytes.Buffer)
	_, err = io.Copy(b, plain)
	if err != nil {
		//return nil, acprotoError(-10, "OpenKXMessage().io.Copy(): ", err)
		return nil, nil, &protoError{value: -10, msg: "OpenKXMessage().io.Copy(): ", err: err}
		//panic(err)
	}

	// XXX TODO
	// get RANDOMNESS bytes, return the random bytes
	newRnd := make([]byte, len(context.key))
	_, err = rand.Read(newRnd)
	if err != nil {
		return nil, nil, &protoError{value: -11, msg: "OpenKXMessage() no randomness to protect the key in memory: ", err: err}
	}

	// XXX TODO: check the extracted buffer size... to sure we're not copying
	// too much into a restricted buffer...
	copy(context.key[:], b.Bytes())

	// Xor the key now..
	for j := 0; j < len(newRnd); j++ {
		context.key[j] = context.key[j] ^ newRnd[j]
	}

	//fmt.Fprintf(os.Stderr, "KEY HEX: %s\n", hex.EncodeToString(b.Bytes()))
	//fmt.Fprintf(os.Stderr, "DECODED UNSEALED: %d\n", len(b.Bytes()))
	//    out = b.Bytes()
	return context, newRnd, nil
}
