// +build go1.4
package acpb

import (
	//"bytes"
	"crypto/rand"
	"fmt"
	"github.com/golang/protobuf/proto" // protobuf is now here.
	"github.com/unix4fun/ac/accp"
	"github.com/unix4fun/ac/ackp"
	//"github.com/unix4fun/ac/acutl"
	//"golang.org/x/crypto/hkdf"   // sha3 is now here.
	//"golang.org/x/crypto/pbkdf2" // sha3 is now here.
	//"golang.org/x/crypto/sha3"   // sha3 is now here.
	//"hash"
	"io"
	"os"
)

func CTSEAL_Handler(acMessageCtReq *AcCipherTextMessageRequest) (acMsgResponse *AcCipherTextMessageResponse, err error) {
	var responseType AcCipherTextMessageResponseAcCTRespMsgType
	responseType = AcCipherTextMessageResponse_CTR_SEAL
	var acctx *ackp.SecKey
	var acBlobArray [][]byte
	var out []byte
	var reqBlobTmp []byte

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
	acctx, ok_a := ackp.ACmap.GetSKMapEntry(reqServ, reqChan)
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

	acrnd, ok_b := ackp.ACmap.GetRDMapEntry(reqServ, reqChan)
	if ok_b == false {
		retErr := acpbError(-2, "CTSEAL_Handler(): no RDMap found!", nil)
		acMsgResponse = &AcCipherTextMessageResponse{
			Type:      &responseType,
			Bada:      proto.Bool(false),
			ErrorCode: proto.Int32(-2),
		}
		fmt.Fprintf(os.Stderr, "[!] CTSEAL -> (R) -2 ! %s\n", retErr.Error())
		return acMsgResponse, retErr
	}

	// XXX test here for message length and send multiple encrypted messages
	// TODO: dont hardcode the limits but well it's a first try
	// back if the original message is too long.
	/*
		if len(out)+14+len(reqChan) > 512 {
			fmt.Fprintf(os.Stderr, "MESSAGE WAYYYYYY TOO LONG LET's SPLIT AND BUILD SEVERAL")
		}
	*/
	//tmpBlobLen := len(reqBlob)
	//:nick!user@host PRIVMSG target :<usable bytes><CRLF>
	msgLen := accp.PredictLenNACL(reqBlob) + len(reqChan) + 14
	nBlock := msgLen/410 + 1

	//for msgLen, nBlock := accp.PredictLenNACL(tmpBlobLen)+len(reqChan)+14, 1; msgLen > 510; msgLen, nBlock = accp.PredictLenNACL(reqBlob)+len(reqChan)+14, nBlock+1 {
	/*
		for ; msgLen > 510; msgLen, nBlock = (accp.PredictLenNACL(reqBlob)+len(reqChan)+14)/nBlock, nBlock+1 {
			fmt.Fprintf(os.Stderr, ">>block size: %d numblock: %d\n", msgLen, nBlock)
		}
		nBlock--
	*/
	// BUG HERE with offsets...
	for j, bSize, bAll, bPtr := 0, len(reqBlob)/nBlock, len(reqBlob), 0; j < nBlock; j, bPtr = j+1, bPtr+bSize {
		if bPtr+bSize+1 >= bAll {
			reqBlobTmp = reqBlob[bPtr:]
			//fmt.Fprintf(os.Stderr, "** %d block[%d:%d]: %s \n", j, bPtr, bAll, reqBlobTmp)
			//fmt.Fprintf(os.Stderr, ">> %d => %c || %d => %c\n", bAll, reqBlob[bAll-1], bAll+1, reqBlob[bAll+1])
			//reqBlob[bPtr:bAll]
		} else {
			reqBlobTmp = reqBlob[bPtr : bPtr+bSize]
			//fmt.Fprintf(os.Stderr, ">>#%d block[%d:%d]: %s \n", j, bPtr, bPtr+bSize, reqBlobTmp)
			//reqBlob[bPtr : bPtr+bSize]
		} // END OF ELSE

		//fmt.Fprintf(os.Stderr, ">> NEW #%d block[%d:%d]: %s \n", j, bPtr, bPtr+len(reqBlobTmp), reqBlobTmp)
		out, err = accp.CreateACMessageNACL(acctx, acrnd, reqBlobTmp, []byte(myNick))
		if err != nil {
			retErr := acpbError(-4, "CTSEAL_Handler(): CreateACMessage() error:", err)
			acMsgResponse = &AcCipherTextMessageResponse{
				Type:      &responseType,
				Bada:      proto.Bool(false),
				ErrorCode: proto.Int32(-4),
			}
			fmt.Fprintf(os.Stderr, "[!] CTSEAL -> (R) -4 ! %s\n", retErr.Error())
			return acMsgResponse, retErr
		}
		acBlobArray = append(acBlobArray, out)
	} // END OF FOR

	/*
			for b, offset := 1, msgLen; b < nBlock; b, offset = b+1, offset+msgLen {
				fmt.Fprintf(os.Stderr, "b: %d - offset: %d => [%d:%d]\n", b, offset, offset-msgLen, offset)
				// 0 : 289
				//   : 289
			}

		//var acBlobArray = make([][]byte, nBlock)
		fmt.Fprintf(os.Stderr, "b: %d - offset: %d => [%d:%d]\n", b, offset, offset-msgLen, offset)
	*/

	//func CreateACMessage(context * SecKey, msg, myNick []byte) (out []BYTE, ERR ERROR) {
	/*
		out, err := accp.CreateACMessage(acctx, acrnd, reqBlob, []byte(myNick))
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

		// even with one reply it's now a [][]byte
		acBlobArray = append(acBlobArray, out)
	*/

	acMsgResponse = &AcCipherTextMessageResponse{
		Type:      &responseType,
		Bada:      proto.Bool(true),
		ErrorCode: proto.Int32(0), // should be good enough for now... but better have a separate field with correct type..
		Nonce:     proto.Uint32(acctx.GetNonce()),
		Blob:      acBlobArray,
	}
	fmt.Fprintf(os.Stderr, "[+] CTSEAL -> (R) 0 ! %s/%s %s's msg sealed\n", reqServ, reqChan, myNick)
	return acMsgResponse, nil
}

func CTOPEN_Handler(acMessageCtReq *AcCipherTextMessageRequest) (acMsgResponse *AcCipherTextMessageResponse, err error) {
	var responseType AcCipherTextMessageResponseAcCTRespMsgType
	responseType = AcCipherTextMessageResponse_CTR_OPEN
	var acctx *ackp.SecKey
	//var acBlobArray [][]byte

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
	acctx, ok_a := ackp.ACmap.GetSKMapEntry(reqServ, channel)
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

	acrnd, ok_b := ackp.ACmap.GetRDMapEntry(reqServ, channel)
	if ok_b == false {
		retErr := acpbError(-2, "CTOPEN_Handler(): no RDMap found!", nil)
		acMsgResponse = &AcCipherTextMessageResponse{
			Type:      &responseType,
			Bada:      proto.Bool(false),
			ErrorCode: proto.Int32(-2),
		}
		fmt.Fprintf(os.Stderr, "[!] CTOPEN -> (R) -2 ! %s\n", retErr.Error())
		return acMsgResponse, retErr
	}

	//func OpenACMessage(context * SecKey, cmsg, peerNick []byte) (out []byte, err error) {
	// XXX TODO: use reqOpt accordingly
	out, err := accp.OpenACMessageNACL(acctx, acrnd, blob, []byte(peernick), []byte(reqOpt))
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

	//acBlobArray = append(acBlobArray, out)

	//fmt.Fprintf(os.Stderr, "OUT: %s\n", out)
	acMsgResponse = &AcCipherTextMessageResponse{
		Type:      &responseType,
		Bada:      proto.Bool(true),
		ErrorCode: proto.Int32(0),
		Nonce:     proto.Uint32(acctx.GetNonce()),
		Blob:      [][]byte{out},
	}
	fmt.Fprintf(os.Stderr, "[+] CTOPEN -> (R) 0 ! %s/%s %s's msg opened\n", reqServ, channel, peernick)
	return acMsgResponse, nil
}

// we use PBKDF2 + SHA3 to derive a key out of the entropy with a crypto/rand salt
// TODO: implement fortuna to feed the PRNG
func CTADD_Handler(acMessageCtReq *AcCipherTextMessageRequest) (acMsgResponse *AcCipherTextMessageResponse, err error) {
	var responseType AcCipherTextMessageResponseAcCTRespMsgType
	responseType = AcCipherTextMessageResponse_CTR_OPEN
	//var acctx * accp.SecKey

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
	skgen := new(ackp.SecretKeyGen)
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

	//acctx := new(accp.SecKey)
	// XXX TODO: handle error...
	acctx, _ := ackp.CreateACContext([]byte(reqChan), 0)

	key := make([]byte, 32)
	io.ReadFull(skgen, key)
	//fmt.Fprintf(os.Stderr, "ReqServ: %s reqChan: %s HEX KEY: %s\n", reqServ, reqChan, hex.EncodeToString(key))

	newRnd := make([]byte, len(key))
	_, err = rand.Read(newRnd)
	if err != nil {
		//return nil, nil, &protoError{value: -11, msg: "OpenKXMessage() no randomness to protect the key in memory: ", err: err}
		retErr := acpbError(-3, "CTADD_Handler(): randomness to protect key failed:", err)
		acMsgResponse = &AcCipherTextMessageResponse{
			Type:      &responseType,
			Bada:      proto.Bool(false),
			ErrorCode: proto.Int32(-3),
		}
		return acMsgResponse, retErr
	}

	acctx.SetKey(key)
	// XOR the key...
	acctx.RndKey(newRnd)

	ackp.ACmap.SetSKMapEntry(reqServ, reqChan, acctx)
	ackp.ACmap.SetRDMapEntry(reqServ, reqChan, newRnd)

	acMsgResponse = &AcCipherTextMessageResponse{
		Type:      &responseType,
		Bada:      proto.Bool(true),
		ErrorCode: proto.Int32(0),
		//Blob:      []byte("OK"),
		Blob: [][]byte{[]byte("OK")}, // this is an array of []byte
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
