package acproto

import (
	"fmt"
	"os"
	//    "log"
	"bytes"
	"code.google.com/p/go.crypto/nacl/box"
	"code.google.com/p/go.crypto/nacl/secretbox"
	"code.google.com/p/go.crypto/sha3"
	"compress/zlib"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"github.com/unix4fun/ac/obf"
	"io"
	"regexp"
	"time"
)

/*
 * Here we start the protocol definition
 */

const (
	MSGHDR_PK = "PK"
	MSGHDR_AC = "AC"
	MSGHDR_KX = "KX"
)

//
//
// this is error handling
//
//
type AcprotoError struct {
	value int    // the error code.
	msg   string // the associated message
	err   error  // called layer error
}

func (ae *AcprotoError) Error() string {
	if ae.err != nil {
		ae.msg = fmt.Sprintf("AcprotoError[%d]: %s:%s\n", ae.value, ae.msg, ae.err.Error())
	} else {
		ae.msg = fmt.Sprintf("AcprotoError[%d]: %s\n", ae.value, ae.msg)
	}
	return ae.msg
}

func (ae *AcprotoError) GetErrorCode() int {
	return ae.value
}

func (ae *AcprotoError) GetErrorMsg() string {
	return ae.Error()
}

func acprotoError(val int, msg string, err error) (ae *AcprotoError) {
	return &AcprotoError{value: val, msg: msg, err: err}
}

type ACMyKeys struct {
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

func (pk *ACMyKeys) GetPubkey() (pubkey *[32]byte) {
	pubkey = pk.pubkey
	return
}

func (pk *ACMyKeys) SetPubkey(pubkey []byte) {
	if len(pubkey) == 32 {
		pk.pubkey = new([32]byte)
		copy(pk.pubkey[:], pubkey)
	}

	// XXX TODO: handle error here...
	pubfp, _ := HashSHA3Data(pubkey)

	// copy and store the public fingerprint..
	copy(pk.pubfp[:], pubfp)
	return
}

func (pk *ACMyKeys) GetPrivkey() (privkey *[32]byte) {
	privkey = pk.privkey
	return privkey
}

func (pk *ACMyKeys) GetPubfp() (pubfp []byte) {
	pubfp = pk.pubfp[:]
	return
}

// if you Println() the struct then it call this as part of the type.
func (pk *ACMyKeys) String() string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "----\n")
	fmt.Fprintf(&b, "ACMyKeys struct @ %p\n", pk)
	fmt.Fprintf(&b, "nick: %s @ %s on %s\n", pk.Nickname, pk.Userhost, pk.Server)
	fmt.Fprintf(&b, "pubkey: %s\n", pk.Pubkey)
	fmt.Fprintf(&b, "privkey: %s\n", hex.EncodeToString(pk.privkey[:]))
	fmt.Fprintf(&b, "created: %l\n", pk.CreaTime.Unix())
	return b.String()
}

type ACMsgContext struct {
	nonce    uint32
	bob      []byte
	key      [32]byte
	CreaTime time.Time
	Overhead int
}

// if you Println() the struct then it call this as part of the type.
func (sk *ACMsgContext) String() string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "----\n")
	fmt.Fprintf(&b, "ACMsgContext struct @ %p\n", sk)
	fmt.Fprintf(&b, "-> bob : %s\n", sk.bob)
	fmt.Fprintf(&b, "-> key : %s\n", hex.EncodeToString(sk.key[:]))
	fmt.Fprintf(&b, "-> nonce : %08x\n", sk.nonce)
	fmt.Fprintf(&b, "-> created: %l\n", sk.CreaTime.Unix())
	return b.String()
}

func (sk *ACMsgContext) GetKey() []byte {
	// XXX TODO here we will be able to get the memory encrypted key instead of
	// plain.
	return sk.key[:]
}

func (sk *ACMsgContext) SetKey(keydata []byte) {
	copy(sk.key[:], keydata[:32])
	return
}

func (sk *ACMsgContext) GetNonce() uint32 {
	return sk.nonce
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
		return nil, acprotoError(-1, "HashSHA3Data().Write(): ", err)
	}
	out = sha3hash.Sum(nil)
	//fmt.Printf("SHA[%d]:%s\n", len(input), hex.EncodeToString(out))
	return
}

// XXX i need to feed the PRNG and use fortuna...
func CreateMyKeys(rnd io.Reader, nickname string, userhost string, server string) (mykeys *ACMyKeys, err error) {
	mykeys = new(ACMyKeys)
	mykeys.pubkey, mykeys.privkey, err = box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, acprotoError(-1, "CreateMyKeys().GenerateKey(): ", err)
	}

	pubfp, err := HashSHA3Data(mykeys.pubkey[:])
	if err != nil {
		return nil, acprotoError(-1, "CreateMyKeys().hash(): ", err)
	}

	// copy and store the public fingerprint..
	copy(mykeys.pubfp[:], pubfp)

	PK, err := CreatePKMessage(mykeys.pubkey[:])
	if err != nil {
		return nil, acprotoError(-3, "CreateMyKeys().CreatePKMessage(): ", err)
	}
	mykeys.Pubkey = string(PK)
	mykeys.Nickname = nickname
	mykeys.Userhost = userhost
	mykeys.Server = server
	mykeys.HasPriv = true
	mykeys.CreaTime = time.Now()

	return mykeys, nil
}

func CreateACContext(channel []byte, nonce uint32) (context *ACMsgContext, err error) {
	context = new(ACMsgContext)
	// TODO XXX: we need to be careful after a key exchange we can re-encrypt a
	// message with the same nonce, so we should give the nonce with the KEX
	// and also update the nonce on every received message
	context.nonce = nonce
	context.bob = channel
	context.Overhead = secretbox.Overhead
	return
}

func CreateACContextWithInputEntropy(channel []byte, input_entropy []byte) (context *ACMsgContext, err error) {
	context = new(ACMsgContext)
	context.nonce = 0
	context.bob = channel
	context.Overhead = secretbox.Overhead

	sha_entropy, err := HashSHA3Data(input_entropy)
	if err != nil {
		return nil, acprotoError(-1, "CreateACContextWithInputEntropy().HashSHA3Data(): ", err)
	}
	copy(context.key[:], sha_entropy)
	return
}

//
// AC Message Format:
// BASE64( 'AC' || 'NONCE_VALUE' || SECRETBOX( KEY, NONCE_AUTH, ZLIB( MSG ) )
//
// Nonce AUTH Format:
// SHA3( 'CHANNEL' || ':' || 'SRC_NICK' || ':' || 'NONCE_VALUE' || ':' || 'HDR_RAW' )
//

func CreateACMessage(context *ACMsgContext, msg, myNick []byte) (out []byte, err error) {
	var noncebyte [24]byte
	hdr, err := obf.Obfuscate([]byte(MSGHDR_AC))
	if err != nil {
		return nil, acprotoError(-1, "CreateACMessage().Obfuscate(): ", err)
	}

	body := new(bytes.Buffer)

	// first let's compress
	zbuf, err := zlib.NewWriterLevel(body, zlib.BestCompression)
	if err != nil {
		return nil, acprotoError(-2, "CreateACMessage().zlib.NewWriterLevel(): ", err)
		//fmt.Printf("PANIIIIC\n")
		//panic(err)
	}

	_, err = zbuf.Write(msg)
	if err != nil {
		return nil, acprotoError(-3, "CreateACMessage().zlib.Write(): ", err)
		//panic(err)
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
	fmt.Fprintf(os.Stderr, "ENCODE NONCE HEX: %s (%s)\n", hex.EncodeToString(nonce_build.Bytes()), nonce_build.Bytes())

	nonce_sha, err := HashSHA3Data(nonce_build.Bytes())
	if err != nil {
		return nil, acprotoError(-4, "CreateACMessage().HashSHA3Data(): ", err)
	}
	copy(noncebyte[:], nonce_sha[:24])
	//fmt.Printf("ENCODE SHA HEX(%d): %s\n", len(body.Bytes()), hex.EncodeToString(nonce_sha))

	// encrypt
	cipher := secretbox.Seal(nil, body.Bytes(), &noncebyte, &context.key)

	buffer := new(bytes.Buffer)
	encoder := base64.NewEncoder(base64.StdEncoding, buffer)
	encoder.Write(hdr)
	binary.Write(encoder, binary.LittleEndian, context.nonce)
	encoder.Write(cipher)
	encoder.Close()

	out = buffer.Bytes()
	//fmt.Printf("AC MSG OUT[%d]: %s\n", len(out), out)
	context.nonce++
	return
}

func OpenACMessage(context *ACMsgContext, cmsg, peerNick, myNick []byte) (out []byte, err error) {
	var noncebyte [24]byte
	var nonceval uint32

	fmt.Fprintf(os.Stderr, "OpenACMessage()\n")
	b64str := make([]byte, base64.StdEncoding.DecodedLen(len(cmsg)))

	b64str_len, err := base64.StdEncoding.Decode(b64str, cmsg)
	if err != nil || b64str_len <= 8 {
		fmt.Fprintf(os.Stderr, "DECODE FUCK || Too Small!\n")
		return nil, acprotoError(-1, "OpenACMessage().B64Decode()||TooSmall: ", err)
		//return
	}

	hdr, err := obf.DeObfuscate(b64str[:4])
	if err != nil {
		fmt.Fprintf(os.Stderr, "CA FOIRE!!!!\n")
		return nil, acprotoError(-2, "OpenACMessage().Deobfuscate(): ", err)
		//panic(err)
		//return
	}

	if len(hdr) != 2 {
		fmt.Fprintf(os.Stderr, "WRONG HEADER")
		// TODO XXX error type and number
		return nil, acprotoError(-3, "OpenACMessage().Hdr(): ", err)
		//return
	}

	if bytes.Compare(hdr, []byte(MSGHDR_AC)) != 0 {
		fmt.Fprintf(os.Stderr, "WRONG HEADER 2")
		// TODO XXX error type and number
		return nil, acprotoError(-4, "OpenACMessage().Hdr(): ", err)
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
		return nil, acprotoError(-8, "OpenACMessage().nonce_get(): ", err)
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
	fmt.Fprintf(os.Stderr, "DECODE NONCE HEX(%d): %s(%s)\n", len(nonce_build.Bytes()), hex.EncodeToString(nonce_build.Bytes()), nonce_build.Bytes())

	nonce_sha, err := HashSHA3Data(nonce_build.Bytes())
	if err != nil {
		return nil, acprotoError(-4, "OpenACMessage().HashSHA3Data(): ", err)
		//return
	}
	copy(noncebyte[:], nonce_sha[:24])
	//fmt.Printf("DECODE SHA HEX: %s\n", hex.EncodeToString(noncebyte[:]))

	//plain = make([]byte, len(b64str[8:])-secretbox.Overhead)
	//bounce := b64str[8:b64str_len]
	//fmt.Printf("LAST BYTE: %02x\n", bounce[len(bounce)-1:len(bounce)])
	//bounce = bounce[:len(bounce)-1]
	//fmt.Printf("B64 LEN %d CIPHER TEXT : %d\n", len(b64str[4:8]), len(bounce))
	//    fmt.Printf("NONCE LEN: %d\n", len(noncebyte))
	//    fmt.Printf("KEY LEN: %d\n", len(context.key))
	packed, ok := secretbox.Open(nil, b64str[8:b64str_len], &noncebyte, &context.key)
	//    fmt.Printf("C EST OK?!?!?\n")
	//    fmt.Println(ok)
	if ok == false {
		return nil, acprotoError(1, "OpenACMessage().SecretOpen(): false ", nil)
	}
	fmt.Fprintf(os.Stderr, "DECODED UNSEALED: %s\n", packed)
	//fmt.Printf("DECODED UNSEALED: %s\n", ret)

	zbuf := bytes.NewBuffer(packed)
	plain, err := zlib.NewReader(zbuf)
	if err != nil {

		//        fmt.Println(err)
		return nil, acprotoError(-5, "OpenACMessage().zlib.NewReader(): ", err)
		//return
	}

	//    fmt.Println(plain)
	b := new(bytes.Buffer)
	_, err = io.Copy(b, plain)
	if err != nil {
		return nil, acprotoError(-6, "OpenACMessage().io.Copy(): ", err)
		//panic(err)
	}
	fmt.Fprintf(os.Stderr, "DECODED UNSEALED: %s\n", b.Bytes())
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

//
// PK Message Format:
// BASE64( 'PK' || ZLIB( PUBKEY ) )
//
// We need to encrypt/build encryption
//

//func Pubkey2Irc(pubkey []byte) (out []byte, err error) {
func CreatePKMessage(pubkey []byte) (out []byte, err error) {
	hdr, _ := obf.Obfuscate([]byte(MSGHDR_PK))
	//fmt.Printf("HEX: %s\n", hex.EncodeToString(hdr))

	body := new(bytes.Buffer)
	zbuf, err := zlib.NewWriterLevel(body, zlib.BestCompression)
	if err != nil {
		return nil, acprotoError(-1, "CreatePKMessage().zlib.NewWriterLevel(): ", err)
	}

	if _, err = zbuf.Write(pubkey); err != nil {
		return nil, acprotoError(-2, "CreatePKMessage().zlib.Write(): ", err)
	}
	zbuf.Close()
	//fmt.Printf("BODY HEX: %s\n", hex.EncodeToString(body.Bytes()))

	buffer := bytes.NewBuffer(hdr)
	_, err = buffer.Write(body.Bytes())
	if err != nil {
		return nil, acprotoError(-3, "CreatePKMessage().FinalMsg(): ", err)
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
		return nil, acprotoError(-1, "OpenPKMessage().B64Decode(): ", err)
		//log.Fatal(err)
		//return
	}
	//    fmt.Printf("DATALEN: %d\n", datalen)

	if datalen < 20 {
		return nil, acprotoError(-2, "OpenPKMessage().B64Decode(): invalid message size ", nil)
		//return
	}

	hdr, err := obf.DeObfuscate(zdata[:4])
	if err != nil {
		return nil, acprotoError(-3, "OpenPKMessage().Deobfuscate(): invalid message size ", nil)
	}
	//fmt.Printf("HDR: %s\n", hdr)

	if len(hdr) != 2 {
		//fmt.Printf("WRONG HEADER")
		return nil, acprotoError(-4, "OpenPKMessage().Hdr(): invalid header", nil)
		//return
	}

	if bytes.Compare(hdr, []byte(MSGHDR_PK)) != 0 {
		//fmt.Printf("WRONG HEADER")
		return nil, acprotoError(-5, "OpenPKMessage().Hdr(): invalid header", nil)
		//return
	}

	zbuf := bytes.NewBuffer(zdata[4:])
	data, err := zlib.NewReader(zbuf)
	defer data.Close()
	if err != nil {
		return nil, acprotoError(-5, "OpenPKMessage().zlib.NewReader(): ", err)
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
		return nil, acprotoError(-6, "OpenPKMessage().io.Copy(): ", err)
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

//
// KX (Key eXchange) Message Format:
// BASE64( 'KX' || 'NONCE_VALUE' || BOX( PEER_PUBKEY, ME_PRIVKEY, NONCE_AUTH, ZLIB( SECRET ) )
//
// Nonce AUTH Format:
// SHA3( 'CHANNEL' || ':' || 'MY_NICK' || ':' || 'PEER_NICK' || ':' || 'NONCE_VALUE' || ':' || 'HDR_RAW' )
//

func CreateKXMessage(context *ACMsgContext, peerPubkey, myPrivkey *[32]byte, channel, myNick, peerNick []byte) (out []byte, err error) {
	var noncebyte [24]byte
	hdr, err := obf.Obfuscate([]byte(MSGHDR_KX))
	if err != nil {
		return nil, acprotoError(-1, "CreateKXMessage().Hdr(): ", err)
	}

	body := new(bytes.Buffer)

	//fmt.Printf("INIT LEN: %d\n", len(body.Bytes()))
	// first let's compress
	//fmt.Printf("MSG(%d): %s\n", len(msg), msg)
	zbuf, err := zlib.NewWriterLevel(body, zlib.BestCompression)
	if err != nil {
		return nil, acprotoError(-2, "CreateKXMessage().zlib.NewWriterLevel(): ", err)
		//panic(err)
	}

	_, err = zbuf.Write(context.key[:])
	if err != nil {
		return nil, acprotoError(-3, "CreateKXMessage().zlib.Write(): ", err)
	}
	zbuf.Close()
	//fmt.Printf("Compressed: %d bytes -> %d bytes\n", n, len(body.Bytes()))

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
		return nil, acprotoError(-4, "CreateKXMessage().HashSHA3Data(): ", err)
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
		return nil, acprotoError(-5, "CreateKXMessage().B64Encode(): ", err)
	}
	binary.Write(encoder, binary.LittleEndian, context.nonce)
	_, err = encoder.Write(cipherKex)
	if err != nil {
		return nil, acprotoError(-6, "CreateKXMessage().B64Encode(): ", err)
	}
	encoder.Close()

	out = buffer.Bytes()
	//fmt.Printf("AC MSG OUT[%d]: %s\n", len(out), out)

	context.nonce++
	return
}

func OpenKXMessage(peerPubkey, myPrivkey *[32]byte, cmsg, channel, myNick, peerNick []byte) (context *ACMsgContext, err error) {
	var noncebyte [24]byte
	var nonceval uint32

	// check that we are indeed
	if peerPubkey == nil || myPrivkey == nil {
		return nil, acprotoError(-1, "OpenKXMessage().invalidPubPrivKeys(): ", err)
	}

	b64str := make([]byte, base64.StdEncoding.DecodedLen(len(cmsg)))
	b64str_len, err := base64.StdEncoding.Decode(b64str, cmsg)
	if err != nil || b64str_len <= 8 {
		return nil, acprotoError(-1, "OpenKXMessage().B64Decode()||TooSmall: ", err)
		//panic(err)
		//return
	}

	hdr, err := obf.DeObfuscate(b64str[:4])
	if err != nil {
		return nil, acprotoError(-2, "OpenKXMessage().Hdr(): ", err)
		//panic(err)
		//return
	}

	if len(hdr) != 2 {
		//fmt.Printf("WRONG HEADER")
		return nil, acprotoError(-3, "OpenKXMessage().Hdr(): ", err)
		//return
	}

	if bytes.Compare(hdr, []byte(MSGHDR_KX)) != 0 {
		//fmt.Printf("WRONG HEADER")
		return nil, acprotoError(-4, "OpenKXMessage().Hdr(): ", err)
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
		return nil, acprotoError(-5, "OpenKXMessage().HashSHA3Data(): ", err)
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
		return nil, acprotoError(-6, "OpenKXMessage().BoxOpen(): ", nil)
		//return
	}
	//    fmt.Printf("DECODE SHA HEX: %s\n", hex.EncodeToString(noncebyte[:]))
	zbuf := bytes.NewBuffer(packed)
	plain, err := zlib.NewReader(zbuf)
	defer plain.Close()
	if err != nil {
		return nil, acprotoError(-7, "OpenKXMessage().zlib.NewReader(): ", err)
		//log.Fatal(err)
		//return
	}

	// XXX some checks are necessary

	nonceBuf := bytes.NewReader(b64str[4:8])
	err = binary.Read(nonceBuf, binary.LittleEndian, &nonceval)
	if err != nil {
		return nil, acprotoError(-8, "OpenKXMessage().Hdr(): ", err)
		//log.Fatal(err)
		//return
	}
	// create the nonce uint32 value from the buffer of the received message
	// XXX TODO are we at the end of the nonce value..
	context, err = CreateACContext(channel, nonceval+1)
	if err != nil {
		return nil, acprotoError(-9, "OpenKXMessage().CreateACContext(): ", err)
		//return
	}

	b := new(bytes.Buffer)
	_, err = io.Copy(b, plain)
	if err != nil {
		return nil, acprotoError(-10, "OpenKXMessage().io.Copy(): ", err)
		//panic(err)
	}

	// XXX TODO: check the extracted buffer size... to sure we're not copying
	// too much into a restricted buffer...
	copy(context.key[:], b.Bytes())

	fmt.Fprintf(os.Stderr, "KEY HEX: %s\n", hex.EncodeToString(b.Bytes()))
	fmt.Fprintf(os.Stderr, "DECODED UNSEALED: %d\n", len(b.Bytes()))
	//    out = b.Bytes()
	return context, nil
}
