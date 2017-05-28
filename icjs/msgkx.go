// +build go1.5

package icjs

import (
	"encoding/json"
	"fmt"
	"github.com/unix4fun/ic/iccp"
	"github.com/unix4fun/ic/ickp"
	"github.com/unix4fun/ic/icutl"
)

type ACKxMessage struct {
	Type     int    `json:"type"`
	MyNick   string `json:"me"`
	PeerNick string `json:"peer"`
	Server   string `json:"server"`
	Channel  string `json:"channel"`
	Blob     string `json:"blob"`
	//Blob     []byte `json:"blob"`
}

type ACKxReply struct {
	Type  int  `json:"type"`
	Bada  bool `json:"bada"`
	Errno int  `json:"errno"`
	//Blob  []byte `json:"blob"`
	Blob  string `json:"blob"`
	Nonce uint32 `json:"nonce"`
}

func (kx *ACKxMessage) validate() error {
	icutl.DebugLog.Printf("CALL [%p] Validate(%d))\n", kx, kx.Type)
	if (len(kx.MyNick) > 0) && (len(kx.PeerNick) > 0) && (len(kx.Server) > 0) && (len(kx.Channel) > 0) {
		switch kx.Type {
		case kxPack:
			return nil
		case kxUnpack:
			if len(kx.Blob) > 0 {
				return nil
			}
		} // end of switch..
	} // end of if...

	icutl.DebugLog.Printf("RET [%p] Validate(%d) -> [Error: Invalid KX message]\n", kx, kx.Type)
	return fmt.Errorf("invalid KX[%d] message", kx.Type)
}

func (kx *ACKxMessage) HandlerKXPACK() (msgReply []byte, err error) {
	icutl.DebugLog.Printf("CALL [%p] HandleKXPACK(%d:%s -> %s (%s/%s))\n",
		kx,
		kx.Type,
		kx.MyNick,
		kx.PeerNick,
		kx.Server,
		kx.Channel)

	err = kx.validate()
	if err != nil {
		msgReply, _ = json.Marshal(&ACKxReply{
			Type:  kxPackReply,
			Bada:  false,
			Errno: -1,
			Blob:  err.Error(),
		})
		icutl.DebugLog.Printf("RET [%p] HandleKXPACK(%d:%s -> %s (%s/%s)) -> [Error: %s]\n",
			kx,
			kx.Type,
			kx.MyNick,
			kx.PeerNick,
			kx.Server,
			kx.Channel, err.Error())
		return
	}
	acctx, ok_a := ickp.ACmap.GetSKMapEntry(kx.Server, kx.Channel)
	me, ok_b := ickp.ACmap.GetPKMapEntry(kx.Server, kx.MyNick)
	peer, ok_c := ickp.ACmap.GetPKMapEntry(kx.Server, kx.PeerNick)
	acrnd, ok_d := ickp.ACmap.GetRDMapEntry(kx.Server, kx.Channel)

	if ok_a == false || ok_b == false || ok_c == false || ok_d == false {
		err = fmt.Errorf("KXPACK_Handler().GetSKMapEntry/GetPKMapEntry(): failed")
		msgReply, _ = json.Marshal(&ACKxReply{
			Type:  kxPackReply,
			Bada:  false,
			Errno: -2,
			Blob:  err.Error(),
		})
		icutl.DebugLog.Printf("RET [%p] HandleKXPACK(%d:%s -> %s (%s/%s)) -> [Error: %s]\n",
			kx,
			kx.Type,
			kx.MyNick,
			kx.PeerNick,
			kx.Server,
			kx.Channel, err.Error())
		return
	}

	kxMsg, err := iccp.CreateKXMessageNACL(acctx, acrnd, peer.GetPubkey(), me.GetPrivkey(), []byte(kx.Channel), []byte(kx.MyNick), []byte(kx.PeerNick))
	if err != nil {
		//err = fmt.Errorf("KXPACK_Handler().CreateKXMessage(): failed")
		msgReply, _ = json.Marshal(&ACKxReply{
			Type:  kxPackReply,
			Bada:  false,
			Errno: -3,
			Blob:  err.Error(),
		})
		icutl.DebugLog.Printf("RET [%p] HandleKXPACK(%d:%s -> %s (%s/%s)) -> [Error: %s]\n",
			kx,
			kx.Type,
			kx.MyNick,
			kx.PeerNick,
			kx.Server,
			kx.Channel, err.Error())
		return
	}

	msgReply, _ = json.Marshal(&ACKxReply{
		Type:  kxPackReply,
		Bada:  true,
		Errno: 0,
		Blob:  string(kxMsg),
		Nonce: acctx.GetNonce(),
	})
	icutl.DebugLog.Printf("RET [%p] HandleKXPACK(%d:%s -> %s (%s/%s)) -> [OK]\n",
		kx,
		kx.Type,
		kx.MyNick,
		kx.PeerNick,
		kx.Server,
		kx.Channel)
	return
}

func (kx *ACKxMessage) HandlerKXUNPACK() (msgReply []byte, err error) {
	//var responseType AcKeyExchangeMessageResponseAcKXRespMsgType
	//responseType = AcKeyExchangeMessageResponse_KXR_UNPACK

	//channel := acMessageKxReq.GetChannel()
	//mynick := acMessageKxReq.GetMynick()
	//peernick := acMessageKxReq.GetPeernick()
	//blobMsg := acMessageKxReq.GetBlob()
	//reqServ := acMessageKxReq.GetServer()

	//icutl.DebugLog.Printf("(CALL) KXUNPACK <- DH( %s/%s <KX:%s> '%s' -> '%s' ) \n", channel, reqServ, blobMsg, peernick, mynick)
	icutl.DebugLog.Printf("CALL [%p] HandleKXUNPACK(%d:%s -> %s[%s] (%s/%s))\n",
		kx,
		kx.Type,
		kx.PeerNick,
		kx.MyNick,
		kx.Blob,
		kx.Server,
		kx.Channel)

	// XXX TODO: missing the server..
	/*
		if len(channel) == 0 || len(mynick) == 0 || len(peernick) == 0 || len(blobMsg) == 0 || len(reqServ) == 0 {
			retErr := &icutl.AcError{Value: -1, Msg: "KXUNPACK_Handler().args(channel|serv|mynick|peernick): 0 bytes", Err: nil}
			acMsgResponse = &AcKeyExchangeMessageResponse{
				Type:      &responseType,
				Bada:      proto.Bool(false),
				ErrorCode: proto.Int32(-1),
			}
			icutl.DebugLog.Printf("(RET[!]) KXUNPACK -> (-1) ! %s\n", retErr.Error())
			return acMsgResponse, retErr
		}
	*/
	err = kx.validate()
	if err != nil {
		msgReply, _ = json.Marshal(&ACKxReply{
			Type:  kxUnpackReply,
			Bada:  false,
			Errno: -1,
			Blob:  err.Error(),
		})
		icutl.DebugLog.Printf("RET [%p] HandleKXUNPACK(%d:%s -> %s[%s] (%s/%s)) -> [Error: %s]\n",
			kx,
			kx.Type,
			kx.PeerNick,
			kx.MyNick,
			kx.Blob,
			kx.Server,
			kx.Channel, err.Error())
		return
	}

	me, ok_b := ickp.ACmap.GetPKMapEntry(kx.Server, kx.MyNick)
	peer, ok_c := ickp.ACmap.GetPKMapEntry(kx.Server, kx.PeerNick)

	if ok_b == false || ok_c == false || peer.GetPubkey() == nil || me.GetPrivkey() == nil {
		/*
			retErr := &icutl.AcError{Value: -2, Msg: "KXUNPACK_Handler().PKMapLookup(mynick|peernick) failure", Err: nil}
			acMsgResponse = &AcKeyExchangeMessageResponse{
				Type:      &responseType,
				Bada:      proto.Bool(false),
				ErrorCode: proto.Int32(-2),
			}
			icutl.DebugLog.Printf("(RET[!]) KXUNPACK -> (-2) ! GetPKMapEntry(%s): %t - GetPKMapEntry(%s): %t\n%s\n", mynick, ok_b, peernick, ok_c, retErr.Error())
		*/

		err = fmt.Errorf("KXUNPACK_Handler().PKMapLookup(mynick|peernick) failure")
		msgReply, _ = json.Marshal(&ACKxReply{
			Type:  kxUnpackReply,
			Bada:  false,
			Errno: -2,
			Blob:  err.Error(),
		})
		//return acMsgResponse, retErr
		return
	}

	// XXX ok this is how we handle private and channel key exchange as in
	// private/queries there is no "channel"
	// we're going to see if it's a channel or private message key exchange
	// if it's channel we build a "channel"
	// KXPACK => mynick=peernick
	// KXUNPACK => peernick=mynick
	//    kx_channel := []byte(channel)
	//    ok_channel, _ :=  iccp.IsValidChannelName(kx_channel)
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

	acctx, acrnd, err := iccp.OpenKXMessageNACL(peer.GetPubkey(), me.GetPrivkey(), []byte(kx.Blob), []byte(kx.Channel), []byte(kx.MyNick), []byte(kx.PeerNick))
	//    acctx, err := iccp.OpenKXMessage(peer.GetPubkey(), me.GetPrivkey(), blobMsg, kx_channel, []byte(mynick), []byte(peernick))
	if err != nil {
		/*
			retErr := &icutl.AcError{Value: -3, Msg: "KXUNPACK_Handler().OpenKXMessage(): ", Err: err}
			acMsgResponse = &AcKeyExchangeMessageResponse{
				Type:      &responseType,
				Bada:      proto.Bool(false),
				ErrorCode: proto.Int32(-3),
			}
			icutl.DebugLog.Printf("(RET[!]) KXUNPACK -> (-3) ! %s\n", retErr.Error())
			return acMsgResponse, retErr
		*/
		msgReply, _ = json.Marshal(&ACKxReply{
			Type:  kxUnpackReply,
			Bada:  false,
			Errno: -3,
			Blob:  err.Error(),
		})
		return
	}

	ickp.ACmap.SetSKMapEntry(kx.Server, kx.Channel, acctx)
	ickp.ACmap.SetRDMapEntry(kx.Server, kx.Channel, acrnd)

	/*`
	acMsgResponse = &AcKeyExchangeMessageResponse{
		Type:      &responseType,
		Bada:      proto.Bool(true),
		ErrorCode: proto.Int32(0),
		Nonce:     proto.Uint32(acctx.GetNonce()),
	}
	// XXX TODO REMOVE THE REAL DISPLAY OF THE KEY!!!!
	icutl.DebugLog.Printf("(RET) KXUNPACK -> (0) ! Key [%s/%s]\n", reqServ, channel)
	return acMsgResponse, nil
	*/
	msgReply, _ = json.Marshal(&ACKxReply{
		Type:  kxUnpackReply,
		Bada:  true,
		Errno: 0,
		Nonce: acctx.GetNonce(),
	})
	icutl.DebugLog.Printf("RET [%p] HandleKXUNPACK(%d:%s -> %s[%s] (%s/%s)) -> [OK]\n",
		kx,
		kx.Type,
		kx.PeerNick,
		kx.MyNick,
		kx.Blob,
		kx.Server,
		kx.Channel)
	return
}

//
//
// Handle KEY Exchange MESSAGES..
//
//
func HandleKXMsg(msg []byte) (msgReply []byte, err error) {
	icutl.DebugLog.Printf("CALL HandleKXMsg(msg[%d]:[%s])\n", len(msg), msg)
	req := &ACKxMessage{}

	// let's unmarshall the message first
	err = json.Unmarshal(msg, req)
	if err != nil {
		icutl.DebugLog.Printf("RET HandlerKXMsg(%s) -> [Error: %s]\n", msg, err.Error())
		msgReply, _ = json.Marshal(&ACKxReply{
			Type:  kxErrReply,
			Bada:  false,
			Errno: -1,
			Blob:  err.Error(),
		})
		return
	}

	switch req.Type {
	case kxPack:
		msgReply, err = req.HandlerKXPACK()
	case kxUnpack:
		msgReply, err = req.HandlerKXUNPACK()
	default:
		err = fmt.Errorf("invalid KX message")
		msgReply, _ = json.Marshal(&ACKxReply{
			Type:  kxErrReply,
			Bada:  false,
			Errno: -2,
			Blob:  err.Error(),
		})
	}

	icutl.DebugLog.Printf("RET HandleKXMsg(msg[%d]:[%s]) -> [reply[%d]: %s]\n", len(msg), msg, len(msgReply), msgReply)
	return
}
