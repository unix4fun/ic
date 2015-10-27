// +build go1.4
package acpb

import (
	"crypto/rand"
	"github.com/golang/protobuf/proto" // protobuf is now here.
	"github.com/unix4fun/ac/accp"
	"github.com/unix4fun/ac/ackp"
	"github.com/unix4fun/ac/acutl"
	"io"
	//"bytes"
	//	"fmt"
	//"github.com/unix4fun/ac/acutl"
	//"golang.org/x/crypto/hkdf"   // sha3 is now here.
	//"golang.org/x/crypto/pbkdf2" // sha3 is now here.
	//"golang.org/x/crypto/sha3"   // sha3 is now here.
	//"hash"
	//	"os"
)

func CTSEAL_Handler(acMessageCtReq *AcCipherTextMessageRequest) (acMsgResponse *AcCipherTextMessageResponse, err error) {
	var responseType AcCipherTextMessageResponseAcCTRespMsgType
	responseType = AcCipherTextMessageResponse_CTR_SEAL
	var acctx *ackp.SecretKey
	var acBlobArray [][]byte
	var out []byte
	var reqBlobTmp []byte

	reqChan := acMessageCtReq.GetChannel()
	myNick := acMessageCtReq.GetNick()
	reqServ := acMessageCtReq.GetServer()
	reqBlob := acMessageCtReq.GetBlob()

	acutl.DebugLog.Printf("(CALL) CTSEAL (%s/%s %s:'%s')\n", reqChan, reqServ, myNick, reqBlob)

	if len(reqChan) == 0 || len(myNick) == 0 || len(reqBlob) == 0 {
		retErr := &acutl.AcError{Value: -1, Msg: "CTSEAL_Handler().args(channel|serv|mynick): 0 bytes", Err: nil}
		acMsgResponse = &AcCipherTextMessageResponse{
			Type:      &responseType,
			Bada:      proto.Bool(false),
			ErrorCode: proto.Int32(-1),
		}
		acutl.DebugLog.Printf("(RET[!]) CTSEAL -> (-1) ! %s\n", retErr.Error())
		return acMsgResponse, retErr
	}

	acctx, ok_a := ackp.ACmap.GetSKMapEntry(reqServ, reqChan)
	if ok_a == false {
		retErr := &acutl.AcError{Value: -2, Msg: "CTSEAL_Handler(): no SKMap found!", Err: nil}
		acMsgResponse = &AcCipherTextMessageResponse{
			Type:      &responseType,
			Bada:      proto.Bool(false),
			ErrorCode: proto.Int32(-2),
		}
		acutl.DebugLog.Printf("(RET[!]) CTSEAL -> (-2) ! %s\n", retErr.Error())
		return acMsgResponse, retErr
	}

	acrnd, ok_b := ackp.ACmap.GetRDMapEntry(reqServ, reqChan)
	if ok_b == false {
		retErr := &acutl.AcError{Value: -3, Msg: "CTSEAL_Handler(): no RDMap found!", Err: nil}
		acMsgResponse = &AcCipherTextMessageResponse{
			Type:      &responseType,
			Bada:      proto.Bool(false),
			ErrorCode: proto.Int32(-3),
		}
		acutl.DebugLog.Printf("(RET[!]) CTSEAL -> (-3) ! %s\n", retErr.Error())
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
			retErr := &acutl.AcError{Value: -4, Msg: "CTSEAL_Handler(): CreateACMessageNACL()!", Err: err}
			acMsgResponse = &AcCipherTextMessageResponse{
				Type:      &responseType,
				Bada:      proto.Bool(false),
				ErrorCode: proto.Int32(-4),
			}
			acutl.DebugLog.Printf("(RET[!]) CTSEAL -> (-4) ! %s\n", retErr.Error())
			return acMsgResponse, retErr
		}
		acBlobArray = append(acBlobArray, out)
	} // END OF FOR

	acMsgResponse = &AcCipherTextMessageResponse{
		Type:      &responseType,
		Bada:      proto.Bool(true),
		ErrorCode: proto.Int32(0), // should be good enough for now... but better have a separate field with correct type..
		Nonce:     proto.Uint32(acctx.GetNonce()),
		Blob:      acBlobArray,
	}
	//fmt.Fprintf(os.Stderr, "[+] CTSEAL -> (R) 0 ! %s/%s %s's msg sealed\n", reqServ, reqChan, myNick)
	acutl.DebugLog.Printf("(RET) CTSEAL -> (0) ! %s/%s %s's msg sealed\n", reqServ, reqChan, myNick)
	return acMsgResponse, nil
}

func CTOPEN_Handler(acMessageCtReq *AcCipherTextMessageRequest) (acMsgResponse *AcCipherTextMessageResponse, err error) {
	var responseType AcCipherTextMessageResponseAcCTRespMsgType
	responseType = AcCipherTextMessageResponse_CTR_OPEN
	var acctx *ackp.SecretKey

	channel := acMessageCtReq.GetChannel()
	peernick := acMessageCtReq.GetNick()
	reqServ := acMessageCtReq.GetServer()
	blob := acMessageCtReq.GetBlob()
	reqOpt := acMessageCtReq.GetOpt() // XXX will be used for myNick

	acutl.DebugLog.Printf("(CALL) CTOPEN %s/%s from %s:'%s' (%s)\n", channel, reqServ, peernick, blob, reqOpt)

	if len(channel) == 0 || len(peernick) == 0 || len(blob) == 0 {
		retErr := &acutl.AcError{Value: -1, Msg: "CTOPEN_Handler().args(channel|serv|mynick): 0 bytes", Err: nil}
		acMsgResponse = &AcCipherTextMessageResponse{
			Type:      &responseType,
			Bada:      proto.Bool(false),
			ErrorCode: proto.Int32(-1),
		}
		acutl.DebugLog.Printf("(RET[!]) CTOPEN -> (-1) ! %s\n", retErr.Error())
		return acMsgResponse, retErr
	}

	//acctx, ok_a := Sk[channel]
	acctx, ok_a := ackp.ACmap.GetSKMapEntry(reqServ, channel)
	if ok_a == false {
		retErr := &acutl.AcError{Value: -2, Msg: "CTOPEN_Handler(): no SKMap Entry found!", Err: nil}
		acMsgResponse = &AcCipherTextMessageResponse{
			Type:      &responseType,
			Bada:      proto.Bool(false),
			ErrorCode: proto.Int32(-2),
		}
		acutl.DebugLog.Printf("(RET[!]) CTOPEN -> (-2) ! %s\n", retErr.Error())
		return acMsgResponse, retErr
	}

	acrnd, ok_b := ackp.ACmap.GetRDMapEntry(reqServ, channel)
	if ok_b == false {
		retErr := &acutl.AcError{Value: -3, Msg: "CTOPEN_Handler(): no RDMap Entry found!", Err: nil}
		acMsgResponse = &AcCipherTextMessageResponse{
			Type:      &responseType,
			Bada:      proto.Bool(false),
			ErrorCode: proto.Int32(-3),
		}
		acutl.DebugLog.Printf("(RET[!]) CTOPEN -> (-3) ! %s\n", retErr.Error())
		return acMsgResponse, retErr
	}

	//func OpenACMessage(context * SecKey, cmsg, peerNick []byte) (out []byte, err error) {
	// XXX TODO: use reqOpt accordingly
	out, err := accp.OpenACMessageNACL(acctx, acrnd, blob, []byte(peernick), []byte(reqOpt))
	if err != nil {
		retErr := &acutl.AcError{Value: -4, Msg: "CTOPEN_Handler(): OpenACMessageNACL() error!", Err: err}
		acMsgResponse = &AcCipherTextMessageResponse{
			Type:      &responseType,
			Bada:      proto.Bool(false),
			ErrorCode: proto.Int32(-4),
		}
		acutl.DebugLog.Printf("(RET[!]) CTOPEN -> (-4) ! %s\n", retErr.Error())
		return acMsgResponse, retErr
	}

	acMsgResponse = &AcCipherTextMessageResponse{
		Type:      &responseType,
		Bada:      proto.Bool(true),
		ErrorCode: proto.Int32(0),
		Nonce:     proto.Uint32(acctx.GetNonce()),
		Blob:      [][]byte{out},
	}
	acutl.DebugLog.Printf("(RET) CTOPEN -> (0) ! %s/%s %s's msg opened\n", reqServ, channel, peernick)
	return acMsgResponse, nil
}

// we use PBKDF2 + SHA3 to derive a key out of the entropy with a crypto/rand salt
// TODO: implement fortuna to feed the PRNG
func CTADD_Handler(acMessageCtReq *AcCipherTextMessageRequest) (acMsgResponse *AcCipherTextMessageResponse, err error) {
	var responseType AcCipherTextMessageResponseAcCTRespMsgType
	responseType = AcCipherTextMessageResponse_CTR_ADD

	reqChan := acMessageCtReq.GetChannel()
	reqNick := acMessageCtReq.GetNick()
	reqServ := acMessageCtReq.GetServer()
	reqBlob := acMessageCtReq.GetBlob()

	acutl.DebugLog.Printf("(CALL) CTADD %s/%s from %s:'%s' (%s)\n", reqChan, reqServ, reqNick, reqBlob)

	if len(reqChan) == 0 || len(reqNick) == 0 || len(reqServ) == 0 {
		retErr := &acutl.AcError{Value: -1, Msg: "CTADD_Handler().args(channel|serv|mynick): 0 bytes", Err: nil}
		acMsgResponse = &AcCipherTextMessageResponse{
			Type:      &responseType,
			Bada:      proto.Bool(false),
			ErrorCode: proto.Int32(-1),
		}
		acutl.DebugLog.Printf("(RET[!]) CTADD -> (-1) ! %s\n", retErr.Error())
		return acMsgResponse, retErr
	}

	// lets derive the key.
	//    randsalt :=  rand.Read()
	//    func (skgen ACSecretKeyGen) Init(input []byte, channel []byte, nick []byte, serv []byte) {
	skgen := new(ackp.KeyGenerator)
	err = skgen.Init([]byte(reqBlob), []byte(reqChan), []byte(reqNick), []byte(reqServ))
	if err != nil {
		retErr := &acutl.AcError{Value: -2, Msg: "CTADD_Handler(): SK generator fail!", Err: err}
		acMsgResponse = &AcCipherTextMessageResponse{
			Type:      &responseType,
			Bada:      proto.Bool(false),
			ErrorCode: proto.Int32(-2),
		}
		acutl.DebugLog.Printf("(RET[!]) CTADD -> (-2) ! %s\n", retErr.Error())
		return acMsgResponse, retErr
	}

	// XXX TODO: handle error or remove it...
	acctx, _ := ackp.CreateACContext([]byte(reqChan), 0)

	key := make([]byte, 32)
	io.ReadFull(skgen, key)

	newRnd := make([]byte, len(key))
	_, err = rand.Read(newRnd)
	if err != nil {
		retErr := &acutl.AcError{Value: -3, Msg: "CTADD_Handler(): randomness fail!", Err: err}
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

	acutl.DebugLog.Printf("(RET) CTADD -> (0) ! %s/%s key added (entropy: '%s')\n", reqServ, reqChan, reqBlob)
	return acMsgResponse, nil
}

//
//
// Handle Key Exchange MESSAGES..
//
//
func HandleACCtMsg(msg []byte) (msgReply []byte, err error) {
	var acReplyCtMsg *AcCipherTextMessageResponse
	acutl.DebugLog.Printf("(CALL) HandleACCtMsg()\n")

	// unpack the old message
	acMessageCtReq := &AcCipherTextMessageRequest{}
	err = proto.Unmarshal(msg, acMessageCtReq)
	if err != nil {
		return nil, err
	}

	switch ctMsg := acMessageCtReq.GetType(); ctMsg {
	case AcCipherTextMessageRequest_CT_SEAL:
		acReplyCtMsg, err = CTSEAL_Handler(acMessageCtReq)
	case AcCipherTextMessageRequest_CT_OPEN:
		acReplyCtMsg, err = CTOPEN_Handler(acMessageCtReq)
	case AcCipherTextMessageRequest_CT_ADD:
		acReplyCtMsg, err = CTADD_Handler(acMessageCtReq)
	default:
		err = &acutl.AcError{Value: -255, Msg: "HandleACCtMsg(): unknown CT request!", Err: nil}
		acutl.DebugLog.Printf("(RET[!]) HandleACCtMsg(): unknown CT request\n")
		return nil, err
	}

	msgReply, err = proto.Marshal(acReplyCtMsg)
	acutl.DebugLog.Printf("(RET) HandleACCtMsg():\n\tacReplyCtMsg: %v\n\tmsgReply: %v\n\terr: %v\n", acReplyCtMsg, msgReply, err)
	return msgReply, err
}
