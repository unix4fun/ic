// +build go1.4
package acpb

import (
	"github.com/golang/protobuf/proto" // protobuf is now here.
	"github.com/unix4fun/ac/accp"
	"github.com/unix4fun/ac/ackp"
	"github.com/unix4fun/ac/acutl"
)

func KXPACK_Handler(acMessageKxReq *AcKeyExchangeMessageRequest) (acMsgResponse *AcKeyExchangeMessageResponse, err error) {
	var responseType AcKeyExchangeMessageResponseAcKXRespMsgType
	responseType = AcKeyExchangeMessageResponse_KXR_PACK

	channel := acMessageKxReq.GetChannel()
	mynick := acMessageKxReq.GetMynick()
	peernick := acMessageKxReq.GetPeernick()
	reqServ := acMessageKxReq.GetServer()
	acutl.DebugLog.Printf("(CALL) KXPACK <- DH( %s/%s <KX> '%s' -> '%s' ) \n", channel, reqServ, mynick, peernick)

	if len(channel) == 0 || len(mynick) == 0 || len(peernick) == 0 || len(reqServ) == 0 {
		retErr := &acutl.AcError{Value: -1, Msg: "KXPACK_Handler().args(channel|serv|mynick|peernick): 0 bytes", Err: nil}
		acMsgResponse = &AcKeyExchangeMessageResponse{
			Type:      &responseType,
			Bada:      proto.Bool(false),
			ErrorCode: proto.Int32(-1),
		}
		acutl.DebugLog.Printf("(RET[!]) KXPACK -> (-1) ! %s\n", retErr.Error())
		return acMsgResponse, retErr
	}

	acctx, ok_a := ackp.ACmap.GetSKMapEntry(reqServ, channel)
	me, ok_b := ackp.ACmap.GetPKMapEntry(reqServ, mynick)
	peer, ok_c := ackp.ACmap.GetPKMapEntry(reqServ, peernick)
	acrnd, ok_d := ackp.ACmap.GetRDMapEntry(reqServ, channel)

	if ok_a == false || ok_b == false || ok_c == false || ok_d == false {
		retErr := &acutl.AcError{Value: -2, Msg: "KXPACK_Handler().GetSKMapEntry/GetPKMapEntry(): failed ", Err: nil}
		acMsgResponse = &AcKeyExchangeMessageResponse{
			Type:      &responseType,
			Bada:      proto.Bool(false),
			ErrorCode: proto.Int32(-2),
		}
		acutl.DebugLog.Printf("(RET[!]) KXPACK -> (-2) ! %s\n", retErr.Error())
		return acMsgResponse, retErr
	}

	// XXX ok this is how we handle private and channel key exchange as in
	// private/queries there is no "channel"
	// we're going to see if it's a channel or private message key exchange
	// if it's channel we build a "channel"
	// KXPACK => mynick=peernick
	// KXUNPACK => peernick=mynick
	//
	// TODO: to move into CreateKXMessage and OpenKXMessage
	//    kx_channel := []byte(channel)
	//    ok_channel, _ :=  accp.IsValidChannelName(kx_channel)
	//    fmt.Printf("[+] KXPACK: is %s a valid channel: %t\n", channel, ok_channel)
	//    if ok_channel == false {
	//        //kx_channel := channel
	//        // nonce building!
	//        kxc_build := new(bytes.Buffer)
	//        kxc_build.Write([]byte(mynick))
	//        kxc_build.WriteByte(byte('='))
	//        kxc_build.Write([]byte(peernick))
	//        kx_channel = kxc_build.Bytes()
	//        fmt.Printf("[+] KXPACK: not a channel, private conversation let's use this: %s\n", kx_channel)
	//    }

	kxMsg, err := accp.CreateKXMessageNACL(acctx, acrnd, peer.GetPubkey(), me.GetPrivkey(), []byte(channel), []byte(mynick), []byte(peernick))
	if err != nil {
		retErr := &acutl.AcError{Value: -3, Msg: "KXPACK_Handler().CreateKXMessage(): ", Err: err}
		acMsgResponse = &AcKeyExchangeMessageResponse{
			Type:      &responseType,
			Bada:      proto.Bool(false),
			ErrorCode: proto.Int32(-3),
		}
		acutl.DebugLog.Printf("(RET[!]) KXPACK -> (-3) ! %s\n", retErr.Error())
		return acMsgResponse, retErr
	}

	acMsgResponse = &AcKeyExchangeMessageResponse{
		Type:      &responseType,
		Bada:      proto.Bool(true),
		Blob:      kxMsg,
		ErrorCode: proto.Int32(0),
		Nonce:     proto.Uint32(acctx.GetNonce()),
	}
	acutl.DebugLog.Printf("(RET) KXPACK -> (0) ! Key [%s/%s] key packed for %s\n", reqServ, channel, peernick)
	return acMsgResponse, nil
}

func KXUNPACK_Handler(acMessageKxReq *AcKeyExchangeMessageRequest) (acMsgResponse *AcKeyExchangeMessageResponse, err error) {
	var responseType AcKeyExchangeMessageResponseAcKXRespMsgType
	responseType = AcKeyExchangeMessageResponse_KXR_PACK

	channel := acMessageKxReq.GetChannel()
	mynick := acMessageKxReq.GetMynick()
	peernick := acMessageKxReq.GetPeernick()
	blobMsg := acMessageKxReq.GetBlob()
	reqServ := acMessageKxReq.GetServer()

	acutl.DebugLog.Printf("(CALL) KXUNPACK <- DH( %s/%s <KX:%s> '%s' -> '%s' ) \n", channel, reqServ, blobMsg, peernick, mynick)

	// XXX TODO: missing the server..
	if len(channel) == 0 || len(mynick) == 0 || len(peernick) == 0 || len(blobMsg) == 0 || len(reqServ) == 0 {
		retErr := &acutl.AcError{Value: -1, Msg: "KXUNPACK_Handler().args(channel|serv|mynick|peernick): 0 bytes", Err: nil}
		acMsgResponse = &AcKeyExchangeMessageResponse{
			Type:      &responseType,
			Bada:      proto.Bool(false),
			ErrorCode: proto.Int32(-1),
		}
		acutl.DebugLog.Printf("(RET[!]) KXUNPACK -> (-1) ! %s\n", retErr.Error())
		return acMsgResponse, retErr
	}

	me, ok_b := ackp.ACmap.GetPKMapEntry(reqServ, mynick)
	peer, ok_c := ackp.ACmap.GetPKMapEntry(reqServ, peernick)

	if ok_b == false || ok_c == false || peer.GetPubkey() == nil || me.GetPrivkey() == nil {
		retErr := &acutl.AcError{Value: -2, Msg: "KXUNPACK_Handler().PKMapLookup(mynick|peernick) failure", Err: nil}
		acMsgResponse = &AcKeyExchangeMessageResponse{
			Type:      &responseType,
			Bada:      proto.Bool(false),
			ErrorCode: proto.Int32(-2),
		}
		acutl.DebugLog.Printf("(RET[!]) KXUNPACK -> (-2) ! GetPKMapEntry(%s): %t - GetPKMapEntry(%s): %t\n%s\n", mynick, ok_b, peernick, ok_c, retErr.Error())
		return acMsgResponse, retErr
	}

	// XXX ok this is how we handle private and channel key exchange as in
	// private/queries there is no "channel"
	// we're going to see if it's a channel or private message key exchange
	// if it's channel we build a "channel"
	// KXPACK => mynick=peernick
	// KXUNPACK => peernick=mynick
	//    kx_channel := []byte(channel)
	//    ok_channel, _ :=  accp.IsValidChannelName(kx_channel)
	//    fmt.Printf("[+] KXUNPACK: is %s a valid channel: %t\n", channel, ok_channel)
	//    if ok_channel == false {
	//        // private channel building!
	//        kxc_build := new(bytes.Buffer)
	//        kxc_build.Write([]byte(peernick))
	//        kxc_build.WriteByte(byte('='))
	//        kxc_build.Write([]byte(mynick))
	//        kx_channel = kxc_build.Bytes()
	//        fmt.Printf("[+] KXUNPACK: not a channel, private conversation let's use this: %s\n", kx_channel)
	//    }

	acctx, acrnd, err := accp.OpenKXMessageNACL(peer.GetPubkey(), me.GetPrivkey(), blobMsg, []byte(channel), []byte(mynick), []byte(peernick))
	//    acctx, err := accp.OpenKXMessage(peer.GetPubkey(), me.GetPrivkey(), blobMsg, kx_channel, []byte(mynick), []byte(peernick))
	if err != nil {
		retErr := &acutl.AcError{Value: -3, Msg: "KXUNPACK_Handler().OpenKXMessage(): ", Err: err}
		acMsgResponse = &AcKeyExchangeMessageResponse{
			Type:      &responseType,
			Bada:      proto.Bool(false),
			ErrorCode: proto.Int32(-3),
		}
		acutl.DebugLog.Printf("(RET[!]) KXUNPACK -> (-3) ! %s\n", retErr.Error())
		return acMsgResponse, retErr
	}

	ackp.ACmap.SetSKMapEntry(reqServ, channel, acctx)
	ackp.ACmap.SetRDMapEntry(reqServ, channel, acrnd)

	acMsgResponse = &AcKeyExchangeMessageResponse{
		Type:      &responseType,
		Bada:      proto.Bool(true),
		ErrorCode: proto.Int32(0),
		Nonce:     proto.Uint32(acctx.GetNonce()),
	}
	// XXX TODO REMOVE THE REAL DISPLAY OF THE KEY!!!!
	acutl.DebugLog.Printf("(RET) KXUNPACK -> (0) ! Key [%s/%s]\n", reqServ, channel)
	return acMsgResponse, nil
}

//
//
// Handle Key Exchange MESSAGES..
//
//
func HandleACKxMsg(msg []byte) (msgReply []byte, err error) {
	var acReplyKxMsg *AcKeyExchangeMessageResponse
	acutl.DebugLog.Printf("(CALL) HandleACKxMsg()\n")

	// unpack the old message
	acMessageKxReq := &AcKeyExchangeMessageRequest{}
	err = proto.Unmarshal(msg, acMessageKxReq)
	if err != nil {
		return nil, err
	}

	switch kxMsg := acMessageKxReq.GetType(); kxMsg {
	case AcKeyExchangeMessageRequest_KX_PACK:
		acReplyKxMsg, err = KXPACK_Handler(acMessageKxReq)
	case AcKeyExchangeMessageRequest_KX_UNPACK:
		acReplyKxMsg, err = KXUNPACK_Handler(acMessageKxReq)
	default:
		err = &acutl.AcError{Value: -255, Msg: "HandleACKxMsg(): unknown KX request!", Err: nil}
		acutl.DebugLog.Printf("(RET[!]) HandleACKxMsg(): unknown KX request\n")
		return nil, err
	}

	msgReply, err = proto.Marshal(acReplyKxMsg)
	acutl.DebugLog.Printf("(RET) HandleACKxMsg():\n\tacReplyKxMsg: %v\n\tmsgReply: %v\n\terr: %v\n", acReplyKxMsg, msgReply, err)
	return msgReply, err
}
