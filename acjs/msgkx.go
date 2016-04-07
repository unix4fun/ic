package acjs

import (
	"encoding/json"
	"fmt"
	"github.com/unix4fun/ac/accp"
	"github.com/unix4fun/ac/ackp"
	"github.com/unix4fun/ac/acutl"
)

type ACKxMessage struct {
	Type     int    `json:"type"`
	MyNick   string `json:"me"`
	PeerNick string `json:"peer"`
	Server   string `json:"server"`
	Channel  string `json:"channel"`
	Blob     []byte `json:"blob"`
}

type ACKxReply struct {
	Type  int    `json:"type"`
	Bada  bool   `json:"bada"`
	Errno int    `json:"errno"`
	Blob  []byte `json:"blob"`
	Nonce uint32 `json:"nonce"`
}

func (kx *ACKxMessage) validate() error {
	acutl.DebugLog.Printf("CALL [%p] Validate(%d))\n", kx, kx.Type)
	if (len(kx.MyNick) > 0) && (len(kx.PeerNick) > 0) && (len(kx.Server) > 0) && (len(kx.Channel) > 0) {
		switch kx.Type {
		case KXPACK:
			return nil
		case KXUNPACK:
			if len(kx.Blob) > 0 {
				return nil
			}
		} // end of switch..
	} // end of if...

	acutl.DebugLog.Printf("RET [%p] Validate(%d) -> [Error: Invalid KX message]\n", kx, kx.Type)
	return fmt.Errorf("Invalid KX[%d] message!\n", kx.Type)
}

func (kx *ACKxMessage) HandlerKXPACK() (msgReply []byte, err error) {
	acutl.DebugLog.Printf("CALL [%p] HandleKXPACK(%d:%s -> %s (%s/%s))\n",
		kx,
		kx.Type,
		kx.MyNick,
		kx.PeerNick,
		kx.Server,
		kx.Channel)

	err = kx.validate()
	if err != nil {
		msgReply, _ = json.Marshal(&ACKxReply{
			Type:  R_KXPACK,
			Bada:  false,
			Errno: -1,
			Blob:  []byte(err.Error()),
		})
		acutl.DebugLog.Printf("RET [%p] HandleKXPACK(%d:%s -> %s (%s/%s)) -> [Error: %s]\n",
			kx,
			kx.Type,
			kx.MyNick,
			kx.PeerNick,
			kx.Server,
			kx.Channel, err.Error())
		return
	}
	acctx, ok_a := ackp.ACmap.GetSKMapEntry(kx.Server, kx.Channel)
	me, ok_b := ackp.ACmap.GetPKMapEntry(kx.Server, kx.MyNick)
	peer, ok_c := ackp.ACmap.GetPKMapEntry(kx.Server, kx.PeerNick)
	acrnd, ok_d := ackp.ACmap.GetRDMapEntry(kx.Server, kx.Channel)

	if ok_a == false || ok_b == false || ok_c == false || ok_d == false {
		err = fmt.Errorf("KXPACK_Handler().GetSKMapEntry/GetPKMapEntry(): failed")
		msgReply, _ = json.Marshal(&ACKxReply{
			Type:  R_KXPACK,
			Bada:  false,
			Errno: -2,
			Blob:  []byte(err.Error()),
		})
		acutl.DebugLog.Printf("RET [%p] HandleKXPACK(%d:%s -> %s (%s/%s)) -> [Error: %s]\n",
			kx,
			kx.Type,
			kx.MyNick,
			kx.PeerNick,
			kx.Server,
			kx.Channel, err.Error())
		return
	}

	kxMsg, err := accp.CreateKXMessageNACL(acctx, acrnd, peer.GetPubkey(), me.GetPrivkey(), []byte(kx.Channel), []byte(kx.MyNick), []byte(kx.PeerNick))
	if err != nil {
		err = fmt.Errorf("KXPACK_Handler().CreateKXMessage(): failed")
		msgReply, _ = json.Marshal(&ACKxReply{
			Type:  R_KXPACK,
			Bada:  false,
			Errno: -3,
			Blob:  []byte(err.Error()),
		})
		acutl.DebugLog.Printf("RET [%p] HandleKXPACK(%d:%s -> %s (%s/%s)) -> [Error: %s]\n",
			kx,
			kx.Type,
			kx.MyNick,
			kx.PeerNick,
			kx.Server,
			kx.Channel, err.Error())
		return
	}

	msgReply, _ = json.Marshal(&ACKxReply{
		Type:  R_KXPACK,
		Bada:  true,
		Errno: 0,
		Blob:  kxMsg,
		Nonce: acctx.GetNonce(),
	})
	acutl.DebugLog.Printf("RET [%p] HandleKXPACK(%d:%s -> %s (%s/%s)) -> [OK]\n",
		kx,
		kx.Type,
		kx.MyNick,
		kx.PeerNick,
		kx.Server,
		kx.Channel)
	return
	return
}

func (kx *ACKxMessage) HandlerKXUNPACK() (msgReply []byte, err error) {
	return
}

//
//
// Handle KEY Exchange MESSAGES..
//
//
func HandleKXMsg(msg []byte) (msgReply []byte, err error) {
	acutl.DebugLog.Printf("CALL HandleKXMsg(msg[%d]:[%s])\n", len(msg), msg)
	req := &ACKxMessage{}

	// let's unmarshall the message first
	err = json.Unmarshal(msg, req)
	if err != nil {
		acutl.DebugLog.Printf("RET HandlerKXMsg(%s) -> [Error: %s]\n", msg, err.Error())
		msgReply, _ = json.Marshal(&ACKxReply{
			Type:  R_KXERR,
			Bada:  false,
			Errno: -1,
			Blob:  []byte(err.Error()),
		})
		return
	}

	switch req.Type {
	case KXPACK:
		msgReply, err = req.HandlerKXPACK()
	case KXUNPACK:
		msgReply, err = req.HandlerKXUNPACK()
	default:
		err = fmt.Errorf("Invalid KX Message.")
		msgReply, _ = json.Marshal(&ACPkReply{
			Type:  R_KXERR,
			Bada:  false,
			Errno: -2,
			Blob:  []byte(err.Error()),
		})
	}

	acutl.DebugLog.Printf("RET HandleKXMsg(msg[%d]:[%s]) -> [reply[%d]: %s]\n", len(msg), msg, len(msgReply), msgReply)
	return
}
