// +build go1.5

package icjs

import (
	"encoding/json"
	"fmt"
	"github.com/unix4fun/ic/icutl"
	"os"
	//	"errors"
	//	"github.com/golang/protobuf/proto" // protobuf is now here.
	//	"github.com/unix4fun/ac/ickp"
	"github.com/unix4fun/ic/ickp"
)

//var ACmap ickp.PSKMap = ickp.ACmap
//var ACrun bool = ickp.ACrun
const (
	_     = iota
	pkMsg // Public Key Messages
	kxMsg // Key eXchange Messages
	ctMsg // Cipher Text Messages
	clMsg // ControL Messages
	qtMsg // Quit Message
	erMsg // Error Message)

	// PK Messages
	pkGen  // REQ: { "type":PKMSG, "payload": "{ type: PKGEN, nick":"eau", "host":"", "server":"freenode" }" }
	pkAdd  // REQ: { "type":PKMSG, "payload": "{ "nick":"eau", "host":"", "server":"freenode", "key":"blob" }" }
	pkList // { "type":PKMSG, "payload": "{ "nick":"", "server":"freenode" }" }
	pkDel  // { "type":PKMSG, "payload": "{ "nick":"eau", "server":"freenode" }" }

	pkGenReply // RSP: { "type":PKMSG, "payload": "{ "type": R_PKGEN, "bada":true,	 "errno":-1, "data":"" }" }
	pkAddReply // RSP: { "type":PKMSG, "payload": "{ "type": R_PKADD, "bada":true, "errno":0, "data":"" }" }
	pkListReply
	pkDelReply

	pkErrReply // ERR: { "type":PKMSG, "payload": "{ "type": R_PKERR, "bada":false, errno:-1, data:"error message" }"

	// KX Messages
	kxPack
	kxPackReply

	kxUnpack
	kxUnpackReply

	kxErrReply

	// CT Messages
	ctSeal
	ctSealReply

	ctOpen
	ctOpenReply

	ctAdd
	ctAddReply

	ctErrReply

	// CL Messages
	clLoad
	clLoadReply

	clSave
	clSaveReply

	clIsAC
	clIsACReply

	clErrReply
)

// ACComHandler defining a communication handler function prototype
// that are used for handling message types.
type ACComHandler func([]byte) ([]byte, error)

//type ACMsgHandler func() ([]byte, error)

var (
	// Map of handler depending on the type of message
	ACComMessageHandlerMap = map[int]ACComHandler{
		pkMsg: HandlePKMsg,
		kxMsg: HandleKXMsg,
		ctMsg: HandleCTMsg,
		clMsg: HandleCLMsg,
		qtMsg: HandleQuitMsg,
	}

	msgType = map[int]string{
		pkMsg: "PKMSG",
		kxMsg: "KXMSG",
		ctMsg: "CTMSG",
		clMsg: "CLMSG",
		qtMsg: "QTMSG",
		erMsg: "ERMSG",

		// PKMSG
		pkGen:       "PKGEN",
		pkGenReply:  "R_PKGEN",
		pkAdd:       "PKADD",
		pkAddReply:  "R_PKADD",
		pkList:      "PKLIST",
		pkListReply: "R_PKLIST",
		pkDel:       "PKDEL",
		pkDelReply:  "R_PKDEL",
		pkErrReply:  "R_PKERR",

		// KXMSG
		kxPack:        "KXPACK",
		kxPackReply:   "R_KXPACK",
		kxUnpack:      "KXUNPACK",
		kxUnpackReply: "R_KXUNPACK",
		kxErrReply:    "R_KXERR",

		// CTMSG
		ctSeal:      "CTSEAL",
		ctSealReply: "R_CTSEAL",
		ctOpen:      "CTOPEN",
		ctOpenReply: "R_CTOPEN",
		ctAdd:       "CTADD",
		ctAddReply:  "R_CTADD",
		ctErrReply:  "R_CTERR",

		// CTLMSG
	}
)

func init() {
	//icutl.InitDebugLog(os.Stderr)

}

// ACComMessage is the struct type defining the enveloppe of a JSON message..
// Type define the type of message.
// Payload the content of that message.
type ACComMessage struct {
	Type    int    `json:"type"`
	Payload []byte `json:"payload"`
}

func (ac *ACComMessage) Validate() (ACComHandler, error) {
	icutl.DebugLog.Printf("CALL [%p] Validate(%d:%s)\n", ac, ac.Type, ac.Payload)
	switch ac.Type {
	case pkMsg, kxMsg, ctMsg, clMsg, qtMsg:
		if len(ac.Payload) > 0 {
			h, ok := ACComMessageHandlerMap[ac.Type]
			if ok == true {
				icutl.DebugLog.Printf("RET [%p] Validate(%d:%s) -> [OK]\n", ac, ac.Type, ac.Payload)
				return h, nil
			}
			icutl.DebugLog.Printf("RET [%p] Validate(%d:%s) -> [Error: No handlers registered]\n", ac, ac.Type, ac.Payload)
		}
	}
	icutl.DebugLog.Printf("RET [%p] Validate(%d:%s) -> [Error: Invalid message.]\n", ac, ac.Type, ac.Payload)
	return nil, fmt.Errorf("invalid message")
}

func HandleACComMsg(msg []byte) (msgReply []byte, err error) {
	icutl.DebugLog.Printf("CALL HandleACMsg(%s)\n", msg)
	req := &ACComMessage{}

	// let's unmarshall the message first
	err = json.Unmarshal(msg, req)
	if err != nil {
		icutl.DebugLog.Printf("RET HandleACMsg(%s) -> [Error: %s]\n", msg, err.Error())
		msgReply, _ = json.Marshal(&ACComMessage{
			Type:    erMsg,
			Payload: []byte(err.Error()),
		})
		return
	}

	handler, err := req.Validate()
	if err != nil {
		icutl.DebugLog.Printf("RET HandleACMsg(%s) -> [Error: %s]\n", msg, err.Error())
		msgReply, _ = json.Marshal(&ACComMessage{
			Type:    erMsg,
			Payload: []byte(err.Error()),
		})
		return
	}

	replyPayload, err := handler(req.Payload)
	if err != nil {
		msgReply, _ = json.Marshal(&ACComMessage{
			Type:    erMsg,
			Payload: replyPayload,
		})
		icutl.DebugLog.Printf("RET HandleACMsg(%s) -> [Error: %s\n\treplyPayload: %s]\n", msg, err.Error(), replyPayload)
		return
	}

	msgReply, err = json.Marshal(&ACComMessage{
		Type:    req.Type,
		Payload: replyPayload,
	})
	icutl.DebugLog.Printf("RET HandleACMsg(%s) -> [reply: %s (%s)]\n", msg, msgReply, replyPayload)
	return
}

// HandleQuitMsg handles QUIT messages
func HandleQuitMsg(msg []byte) (msgReply []byte, err error) {
	icutl.DebugLog.Printf("CALL HandleQTMsg(msg[%d]:[%s])\n", len(msg), msg)
	ickp.ACrun = false
	// TODO: send acknowledgment with the exact same message type.
	icutl.DebugLog.Printf("RET HandleQTMsg(msg[%d]:[%s]) -> [reply[%d]: %s]\n", len(msg), msg, len(msgReply), msgReply)
	return
}

func HandleStdin() (err error) {
	icutl.DebugLog.Printf("CALL HandleStdin()\n")

	buf := make([]byte, 4096)
	//	for {
	n, err := os.Stdin.Read(buf[0:])
	if err != nil {
		icutl.DebugLog.Printf("RET HandleStdin(): [Error: %s]\n", err.Error())
		return err
	}
	// TODO:
	// NewACComMessage()

	msgReply, acErr := HandleACComMsg(buf[:n])
	// XXX seems like a useless condition here.. review and fix..
	if acErr != nil {
		//fmt.Println(acErr)
		if msgReply != nil {
			os.Stdout.Write(msgReply)
			// TODO to remove...
			fmt.Fprintf(os.Stderr, "\n")
		}
		icutl.DebugLog.Printf("RET HandleStdin(): [Error: %s]\n", acErr.Error())
		return acErr
	}

	os.Stdout.Write(msgReply)
	// TODO to remove...
	fmt.Fprintf(os.Stderr, "\n")
	return nil
	//	} /* end of for() */
	// XXX need to return Error.New() really...
	//	return nil
}
