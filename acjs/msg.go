package acjs

import (
	"encoding/json"
	"fmt"
	"github.com/unix4fun/ac/acutl"
	"os"
	//	"errors"
	//	"github.com/golang/protobuf/proto" // protobuf is now here.
	//	"github.com/unix4fun/ac/ackp"
)

//var ACmap ackp.PSKMap = ackp.ACmap
//var ACrun bool = ackp.ACrun
const (
	_     = iota
	PKMSG // Public Key Messages
	KXMSG // Key eXchange Messages
	CTMSG // Cipher Text Messages
	CLMSG // ControL Messages
	QTMSG // Quit Message
	ERMSG // Error Message)

	// PK Messages
	PKGEN  // REQ: { "type":PKMSG, "payload": "{ type: PKGEN, nick":"eau", "host":"", "server":"freenode" }" }
	PKADD  // REQ: { "type":PKMSG, "payload": "{ "nick":"eau", "host":"", "server":"freenode", "key":"blob" }" }
	PKLIST // { "type":PKMSG, "payload": "{ "nick":"", "server":"freenode" }" }
	PKDEL  // { "type":PKMSG, "payload": "{ "nick":"eau", "server":"freenode" }" }

	R_PKGEN // RSP: { "type":PKMSG, "payload": "{ "type": R_PKGEN, "bada":true,	 "errno":-1, "data":"" }" }
	R_PKADD // RSP: { "type":PKMSG, "payload": "{ "type": R_PKADD, "bada":true, "errno":0, "data":"" }" }
	R_PKLIST
	R_PKDEL

	R_PKERR // ERR: { "type":PKMSG, "payload": "{ "type": R_PKERR, "bada":false, errno:-1, data:"error message" }"

	// KX Messages
	KXPACK
	R_KXPACK

	KXUNPACK
	R_KXUNPACK

	R_KXERR

	// CT Messages
	CTSEAL
	R_CTSEAL

	CTOPEN
	R_CTOPEN

	CTADD
	R_CTADD

	R_CTERR

	// CL Messages
	CLLOAD
	R_CLLOAD

	CLSAVE
	R_CLSAVE

	CLIAC
	R_CLIAC

	R_CLERR
)

// function pointers
type ACComHandler func([]byte) ([]byte, error)
type ACMsgHandler func() ([]byte, error)

var (
	// Map of handler depending on the type of message
	ACComMessageHandlerMap = map[int]ACComHandler{
		PKMSG: HandlePKMsg,
		KXMSG: HandleKXMsg,
		CTMSG: HandleCTMsg,
		CLMSG: HandleCLMsg,
		QTMSG: HandleQuitMsg,
	}

	/*
		ACPkMessageHandlerMap = map[int]ACMsgHandler{
			PKGEN: nil,
		}
	*/

	MsgType = map[int]string{
		PKMSG: "PKMSG",
		KXMSG: "KXMSG",
		CTMSG: "CTMSG",
		CLMSG: "CLMSG",
		QTMSG: "QTMSG",
		ERMSG: "ERMSG",

		// PKMSG
		PKGEN:    "PKGEN",
		R_PKGEN:  "R_PKGEN",
		PKADD:    "PKADD",
		R_PKADD:  "R_PKADD",
		PKLIST:   "PKLIST",
		R_PKLIST: "R_PKLIST",
		PKDEL:    "PKDEL",
		R_PKDEL:  "R_PKDEL",
		R_PKERR:  "R_PKERR",

		// KXMSG
		KXPACK:     "KXPACK",
		R_KXPACK:   "R_KXPACK",
		KXUNPACK:   "KXUNPACK",
		R_KXUNPACK: "R_KXUNPACK",
		R_KXERR:    "R_KXERR",

		// CTMSG
		CTSEAL:   "CTSEAL",
		R_CTSEAL: "R_CTSEAL",
		CTOPEN:   "CTOPEN",
		R_CTOPEN: "R_CTOPEN",
		CTADD:    "CTADD",
		R_CTADD:  "R_CTADD",
		R_CTERR:  "R_CTERR",

		// CTLMSG
	}
)

func init() {
	acutl.InitDebugLog(os.Stderr)

}

// the enveloppe of JSON messages..
type ACComMessage struct {
	Type    int    `json:"type"`
	Payload []byte `json:"payload"`
}

func (ac *ACComMessage) Validate() (ACComHandler, error) {
	acutl.DebugLog.Printf("CALL [%p] Validate(%d:%s)\n", ac, ac.Type, ac.Payload)
	switch ac.Type {
	case PKMSG, KXMSG, CTMSG, CLMSG, QTMSG:
		if len(ac.Payload) > 0 {
			h, ok := ACComMessageHandlerMap[ac.Type]
			if ok == true {
				acutl.DebugLog.Printf("RET [%p] Validate(%d:%s) -> [OK]\n", ac, ac.Type, ac.Payload)
				return h, nil
			} else {
				acutl.DebugLog.Printf("RET [%p] Validate(%d:%s) -> [Error: No handlers registered]\n", ac, ac.Type, ac.Payload)
			}
		}
	}
	acutl.DebugLog.Printf("RET [%p] Validate(%d:%s) -> [Error: Invalid message.]\n", ac, ac.Type, ac.Payload)
	return nil, fmt.Errorf("Invalid message.")
}

func HandleACComMsg(msg []byte) (msgReply []byte, err error) {
	acutl.DebugLog.Printf("CALL HandleACMsg(%s)\n", msg)
	req := &ACComMessage{}

	// let's unmarshall the message first
	err = json.Unmarshal(msg, req)
	if err != nil {
		acutl.DebugLog.Printf("RET HandleACMsg(%s) -> [Error: %s]\n", msg, err.Error())
		msgReply, _ = json.Marshal(&ACComMessage{
			Type:    ERMSG,
			Payload: []byte(err.Error()),
		})
		return
	}

	handler, err := req.Validate()
	if err != nil {
		acutl.DebugLog.Printf("RET HandleACMsg(%s) -> [Error: %s]\n", msg, err.Error())
		msgReply, _ = json.Marshal(&ACComMessage{
			Type:    ERMSG,
			Payload: []byte(err.Error()),
		})
		return
	}

	replyPayload, err := handler(req.Payload)
	if err != nil {
		msgReply, _ = json.Marshal(&ACComMessage{
			Type:    ERMSG,
			Payload: replyPayload,
		})
		acutl.DebugLog.Printf("RET HandleACMsg(%s) -> [Error: %s\n\treplyPayload: %s]\n", msg, err.Error(), replyPayload)
		return
	}

	msgReply, err = json.Marshal(&ACComMessage{
		Type:    req.Type,
		Payload: replyPayload,
	})
	acutl.DebugLog.Printf("RET HandleACMsg(%s) -> [reply: %s (%s)]\n", msg, msgReply, replyPayload)
	return
}

//
//
// Handle Quit MESSAGES..
//
//
func HandleQuitMsg(msg []byte) (msgReply []byte, err error) {
	acutl.DebugLog.Printf("CALL HandleQTMsg(msg[%d]:[%s])\n", len(msg), msg)
	acutl.DebugLog.Printf("RET HandleQTMsg(msg[%d]:[%s]) -> [reply[%d]: %s]\n", len(msg), msg, len(msgReply), msgReply)
	return
}

func HandleStdin() (err error) {
	acutl.DebugLog.Printf("CALL HandleStdin()\n")

	buf := make([]byte, 4096)
	for {
		n, err := os.Stdin.Read(buf[0:])
		if err != nil {
			acutl.DebugLog.Printf("RET HandleStdin(): [Error: %s]\n", err.Error())
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
			acutl.DebugLog.Printf("RET HandleStdin(): [Error: %s]\n", acErr.Error())
			return acErr
		}

		os.Stdout.Write(msgReply)
		// TODO to remove...
		fmt.Fprintf(os.Stderr, "\n")
		//		acutl.DebugLog.Printf("2143241\n")
		return nil
	} /* end of for() */
	// XXX need to return Error.New() really...
	return nil
}

/*
func main() {
	fmt.Printf("prout proutprout\n")
	for k, v := range MsgType {
		fmt.Printf("[%d]:%s\n", k, v)
	}

	HandleStdin()
}
*/
