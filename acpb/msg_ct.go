package acpb

import (
	"fmt"
	"os"
	//    "log"
	//    "net"
	//    "time"
	"bytes"
	"crypto/rand"
	"hash"
	"io"
	//    "encoding/hex"
	"code.google.com/p/go.crypto/hkdf"
	"code.google.com/p/go.crypto/pbkdf2"
	"code.google.com/p/go.crypto/sha3"
	"code.google.com/p/goprotobuf/proto"
	"github.com/unix4fun/ac/proto"
)

func CTSEAL_Handler(acMessageCtReq *AcCipherTextMessageRequest) (acMsgResponse *AcCipherTextMessageResponse, err error) {
	var responseType AcCipherTextMessageResponseAcCTRespMsgType
	responseType = AcCipherTextMessageResponse_CTR_SEAL
	var acctx *acproto.ACMsgContext

	reqChan := acMessageCtReq.GetChannel()
	myNick := acMessageCtReq.GetNick()
	reqServ := acMessageCtReq.GetServer()
	reqBlob := acMessageCtReq.GetBlob()

	fmt.Fprintf(os.Stderr, "[+] CTSEAL %s/%s %s:'%s'\n", reqChan, reqServ, myNick, reqBlob)

	if len(reqChan) == 0 || len(myNick) == 0 || len(reqBlob) == 0 {
		retErr := acpbError(-1, "CTSEAL_Handler().args(channel|serv|mynick): 0 bytes", nil)
		acMsgResponse = &AcCipherTextMessageResponse{
			Type:      &responseType,
			Bada:      proto.Bool(false),
			ErrorCode: proto.Int32(-1),
		}
		fmt.Fprintf(os.Stderr, "[!] CTSEAL -> (R) -1 ! %s\n", retErr.Error())
		return acMsgResponse, retErr
	}

	//acctx, ok_a := Sk[channel]
	acctx, ok_a := ACmap.GetSKMapEntry(reqServ, reqChan)
	if ok_a == false {
		retErr := acpbError(-2, "CTSEAL_Handler(): no SKMap found!", nil)
		acMsgResponse = &AcCipherTextMessageResponse{
			Type:      &responseType,
			Bada:      proto.Bool(false),
			ErrorCode: proto.Int32(-2),
		}
		fmt.Fprintf(os.Stderr, "[!] CTSEAL -> (R) -2 ! %s\n", retErr.Error())
		return acMsgResponse, retErr
	}

	//func CreateACMessage(context * ACMsgContext, msg, myNick []byte) (out []byte, err error) {
	out, err := acproto.CreateACMessage(acctx, reqBlob, []byte(myNick))
	if err != nil {
		retErr := acpbError(-3, "CTSEAL_Handler(): CreateACMessage() error:", err)
		acMsgResponse = &AcCipherTextMessageResponse{
			Type:      &responseType,
			Bada:      proto.Bool(false),
			ErrorCode: proto.Int32(-3),
		}
		fmt.Fprintf(os.Stderr, "[!] CTSEAL -> (R) -3 ! %s\n", retErr.Error())
		return acMsgResponse, retErr
	}

	acMsgResponse = &AcCipherTextMessageResponse{
		Type:      &responseType,
		Bada:      proto.Bool(true),
		ErrorCode: proto.Int32(0), // should be good enough for now... but better have a separate field with correct type..
		Nonce:     proto.Uint32(acctx.GetNonce()),
		Blob:      out,
	}
	fmt.Fprintf(os.Stderr, "[+] CTSEAL -> (R) 0 ! %s/%s %s's msg sealed\n", reqServ, reqChan, myNick)
	return acMsgResponse, nil
}

func CTOPEN_Handler(acMessageCtReq *AcCipherTextMessageRequest) (acMsgResponse *AcCipherTextMessageResponse, err error) {
	var responseType AcCipherTextMessageResponseAcCTRespMsgType
	responseType = AcCipherTextMessageResponse_CTR_OPEN
	var acctx *acproto.ACMsgContext

	//    fmt.Fprintf(os.Stderr, "CTOPEN Message: let's give the key\n")
	//    fmt.Fprintf(os.Stderr, "from nick: %s\n", acMessageCtReq.GetNick())
	//    fmt.Fprintf(os.Stderr, "blob: %s\n", acMessageCtReq.GetBlob())
	//    fmt.Fprintf(os.Stderr, "channel: %s\n", acMessageCtReq.GetChannel())

	channel := acMessageCtReq.GetChannel()
	peernick := acMessageCtReq.GetNick()
	reqServ := acMessageCtReq.GetServer()
	blob := acMessageCtReq.GetBlob()
	reqOpt := acMessageCtReq.GetOpt() // XXX will be used for myNick

	fmt.Fprintf(os.Stderr, "[+] CTOPEN %s/%s from %s:'%s' (%s)\n", channel, reqServ, peernick, blob, reqOpt)

	//    fmt.Fprintf(os.Stderr, "reqOpt VALUE: %p\n", reqOpt)
	//    fmt.Println(reqOpt)

	if len(channel) == 0 || len(peernick) == 0 || len(blob) == 0 {
		retErr := acpbError(-1, "CTOPEN_Handler().args(channel|serv|mynick): 0 bytes", nil)
		acMsgResponse = &AcCipherTextMessageResponse{
			Type:      &responseType,
			Bada:      proto.Bool(false),
			ErrorCode: proto.Int32(-1),
		}
		fmt.Fprintf(os.Stderr, "[!] CTOPEN -> (R) -1 ! %s\n", retErr.Error())
		return acMsgResponse, retErr
	}

	//acctx, ok_a := Sk[channel]
	acctx, ok_a := ACmap.GetSKMapEntry(reqServ, channel)
	if ok_a == false {
		retErr := acpbError(-2, "CTOPEN_Handler(): no SKMap Entry found!", nil)
		acMsgResponse = &AcCipherTextMessageResponse{
			Type:      &responseType,
			Bada:      proto.Bool(false),
			ErrorCode: proto.Int32(-2),
		}
		fmt.Fprintf(os.Stderr, "[!] CTOPEN -> (R) -2 ! %s\n", retErr.Error())
		return acMsgResponse, retErr
	}

	//func OpenACMessage(context * ACMsgContext, cmsg, peerNick []byte) (out []byte, err error) {
	// XXX TODO: use reqOpt accordingly
	out, err := acproto.OpenACMessage(acctx, blob, []byte(peernick), []byte(reqOpt))
	if err != nil {
		//fmt.Println(err)
		retErr := acpbError(-3, "CTOPEN_Handler(): OpenACMessage() error !", err)
		acMsgResponse = &AcCipherTextMessageResponse{
			Type:      &responseType,
			Bada:      proto.Bool(false),
			ErrorCode: proto.Int32(-3),
		}
		fmt.Fprintf(os.Stderr, "[!] CTOPEN -> (R) -3 ! %s\n", retErr.Error())
		return acMsgResponse, retErr
	}

	//fmt.Fprintf(os.Stderr, "OUT: %s\n", out)
	acMsgResponse = &AcCipherTextMessageResponse{
		Type:      &responseType,
		Bada:      proto.Bool(true),
		ErrorCode: proto.Int32(0),
		Nonce:     proto.Uint32(acctx.GetNonce()),
		Blob:      out,
	}
	fmt.Fprintf(os.Stderr, "[+] CTOPEN -> (R) 0 ! %s/%s %s's msg opened\n", reqServ, channel, peernick)
	return acMsgResponse, nil
}

type ACSecretKeyGen struct {
	hash        func() hash.Hash
	channel     []byte
	nick        []byte
	server      []byte
	input       []byte
	input_pbkdf []byte
	//    prng []byte
	info_hkdf []byte
}

func (skgen *ACSecretKeyGen) Init(input []byte, channel []byte, nick []byte, serv []byte) (err error) {
	//skgen.hash = sha3.NewKeccak256
    // go.crypto changed it... mlgrmlbmlbm
	skgen.hash = sha3.New256

	if input != nil {
		skgen.input = make([]byte, len(input))
		copy(skgen.input, input)
	}

	if channel != nil {
		skgen.channel = make([]byte, len(channel))
		copy(skgen.channel, channel)
	}

	if nick != nil {
		skgen.nick = make([]byte, len(nick))
		copy(skgen.nick, nick)
	}

	if serv != nil {
		skgen.server = make([]byte, len(serv))
		copy(skgen.server, serv)
	}

	prng := make([]byte, 256)
	_, err = io.ReadFull(rand.Reader, prng)
	if err != nil {
		return err
		//        fmt.Fprintf(os.Stderr, "POUET POUET Error")
		//        fmt.Println(err)
	}

	//    fmt.Fprintf(os.Stderr, "read %d random bytes\n", n)
	//dk := pbkdf2.Key([]byte("some password"), salt, 4096, 32, sha1.New)
	//func Key(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte
	// XXX TODO be sure of the PBKDF2 FUNCTION CALL ARGUMENTS...
	skgen.input_pbkdf = pbkdf2.Key(skgen.input, prng, 4096, 32, skgen.hash)
	//    fmt.Fprintf(os.Stderr, "PBKDF LEN: %d\n", len(skgen.input_pbkdf))

	// in Read() we will apply the HKDF function.. onto the PBKDF2 derived key.
	str_build := new(bytes.Buffer)
	str_build.Write(serv)
	str_build.WriteByte(byte(':'))
	str_build.Write(nick)
	str_build.WriteByte(byte(':'))
	str_build.Write(channel)

	skgen.info_hkdf, err = acproto.HashSHA3Data(str_build.Bytes())
	if err != nil {
		//fmt.Fprintf(os.Stderr, "HashSHA3ERRORRRR\n")
		//        fmt.Println(err)
		return err
	}

	//    fmt.Fprintf(os.Stderr, "eveyrthing is inited corectly!\n")
	return nil
}

// XXX TODO: return err if init() or Reset() has not been called
func (skgen *ACSecretKeyGen) Read(p []byte) (n int, err error) {
	prng := make([]byte, 256)
	n, err = io.ReadFull(rand.Reader, prng)
	if err != nil {
		//fmt.Fprintf(os.Stderr, "POUET POUET PROUT Error")
		//fmt.Println(err)
		return n, err
	}

	my_hkdf := hkdf.New(skgen.hash, skgen.input_pbkdf, prng, skgen.info_hkdf)
	n, err = io.ReadFull(my_hkdf, p)
	return n, err
}

// we use PBKDF2 + SHA3 to derive a key out of the entropy with a crypto/rand salt
// TODO: implement fortuna to feed the PRNG
func CTADD_Handler(acMessageCtReq *AcCipherTextMessageRequest) (acMsgResponse *AcCipherTextMessageResponse, err error) {
	var responseType AcCipherTextMessageResponseAcCTRespMsgType
	responseType = AcCipherTextMessageResponse_CTR_OPEN
	//var acctx * acproto.ACMsgContext

	//fmt.Fprintf(os.Stderr, "CTADD Message: let's give the key\n")
	//fmt.Fprintf(os.Stderr, "from myNick: %s\n", acMessageCtReq.GetNick())
	//fmt.Fprintf(os.Stderr, "blob: %s\n", acMessageCtReq.GetBlob())
	//fmt.Fprintf(os.Stderr, "channel: %s\n", acMessageCtReq.GetChannel())

	reqChan := acMessageCtReq.GetChannel()
	reqNick := acMessageCtReq.GetNick()
	reqServ := acMessageCtReq.GetServer()
	reqBlob := acMessageCtReq.GetBlob()

	fmt.Fprintf(os.Stderr, "[+] CTADD %s/%s from %s:'%s' (%s)\n", reqChan, reqServ, reqNick, reqBlob)

	if len(reqChan) == 0 || len(reqNick) == 0 || len(reqServ) == 0 {
		retErr := acpbError(-1, "CTADD_Handler().args(channel|serv|mynick): 0 bytes", nil)
		acMsgResponse = &AcCipherTextMessageResponse{
			Type:      &responseType,
			Bada:      proto.Bool(false),
			ErrorCode: proto.Int32(-1),
		}
		return acMsgResponse, retErr
	}

	// lets derive the key.
	//    randsalt :=  rand.Read()
	//    func (skgen ACSecretKeyGen) Init(input []byte, channel []byte, nick []byte, serv []byte) {
	skgen := new(ACSecretKeyGen)
	err = skgen.Init([]byte(reqBlob), []byte(reqChan), []byte(reqNick), []byte(reqServ))
	if err != nil {
		retErr := acpbError(-2, "CTADD_Handler(): SK generator fail:", err)
		acMsgResponse = &AcCipherTextMessageResponse{
			Type:      &responseType,
			Bada:      proto.Bool(false),
			ErrorCode: proto.Int32(-2),
		}
		return acMsgResponse, retErr
	}

	//acctx := new(acproto.ACMsgContext)
	// XXX TODO: handle error...
	acctx, _ := acproto.CreateACContext([]byte(reqChan), 0)

	key := make([]byte, 32)
	io.ReadFull(skgen, key)
	//fmt.Fprintf(os.Stderr, "ReqServ: %s reqChan: %s HEX KEY: %s\n", reqServ, reqChan, hex.EncodeToString(key))
	acctx.SetKey(key)
	ACmap.SetSKMapEntry(reqServ, reqChan, acctx)

	acMsgResponse = &AcCipherTextMessageResponse{
		Type:      &responseType,
		Bada:      proto.Bool(true),
		ErrorCode: proto.Int32(0),
		Blob:      []byte("OK"),
	}

	fmt.Fprintf(os.Stderr, "[+] CTADD -> (R) 0 ! %s/%s key added (entropy: '%s')\n", reqServ, reqChan, reqBlob)
	return acMsgResponse, nil
}

//
//
// Handle Key Exchange MESSAGES..
//
//
func HandleACCtMsg(msg []byte) (msgReply []byte, err error) {
	var acReplyCtMsg *AcCipherTextMessageResponse
	fmt.Fprintf(os.Stderr, "HandleACPkMsg()\n")

	// unpack the old message
	acMessageCtReq := &AcCipherTextMessageRequest{}
	proto.Unmarshal(msg, acMessageCtReq)

	switch ctMsg := acMessageCtReq.GetType(); ctMsg {
	case AcCipherTextMessageRequest_CT_SEAL:
		fmt.Fprintf(os.Stderr, "SEAL CT Message:!\n")
		// TODO we don't handle errors correctly yet...
		acReplyCtMsg, err = CTSEAL_Handler(acMessageCtReq)
	case AcCipherTextMessageRequest_CT_OPEN:
		fmt.Fprintf(os.Stderr, "OPEN CT Message:!\n")
		// TODO we don't handle errors correctly yet...
		acReplyCtMsg, err = CTOPEN_Handler(acMessageCtReq)
	case AcCipherTextMessageRequest_CT_ADD:
		fmt.Fprintf(os.Stderr, "ADD CT KEY Message:!\n")
		// TODO we don't handle errors correctly yet...
		acReplyCtMsg, err = CTADD_Handler(acMessageCtReq)
	default:
		fmt.Fprintf(os.Stderr, "UNKNOWN Message: WTF?!?!\n")
		// TODO need to send a valid reponse with error -255
	}

	msgReply, err = proto.Marshal(acReplyCtMsg)
	return msgReply, err
}
