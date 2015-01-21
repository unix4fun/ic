// +build go1.2
//go:generate protoc --go_out=. ac.proto
package acpb

import (
	"fmt"
	"os"
	//    "log"
	//    "net"
	//    "encoding/hex"
	//    "arsene/ac/proto"
	"code.google.com/p/goprotobuf/proto"
)

// it's temporary until my design looks better
type AcPBError struct {
	value int    // the error code.
	msg   string // the associated message
	err   error  // called layer error
}

func (ae AcPBError) Error() string {
	if ae.err != nil {
		ae.msg = fmt.Sprintf("AcPBError[%d]: %s:%s\n", ae.value, ae.msg, ae.err.Error())
	} else {
		ae.msg = fmt.Sprintf("AcPBError[%d]: %s\n", ae.value, ae.msg)
	}
	return ae.msg
}

func acpbError(val int, msg string, err error) (ae *AcPBError) {
	return &AcPBError{value: val, msg: msg, err: err}
}

// this function will reply on the socket directly..
// reply a packed ArseneCryptoMessage message to be sent by calling function.
// HANDLE ARSENE CRYPTO MESSAGES
func HandleACMsg(msg []byte) (msgReply []byte, err error) {
	var responseType ArseneCryptoMessageAcMessageType
	//fmt.Fprintf(os.Stderr, "[+] HandleACMsg() -> Unmarshal()\n")

	// this is the beginning of the envelope response packet
	acMessageEnvelope := &ArseneCryptoMessage{}
	err = proto.Unmarshal(msg, acMessageEnvelope)

	// we cannot unmarshal this message probably shit, let's reply...
	if err != nil {
		retErr := acpbError(-1, "HandleACMsg().Unmarshall(ENVP): ", err)

		// build up response
		responseType = ArseneCryptoMessage_AC_ERROR
		acMessageEnvelope.Reset()
		acMessageEnvelope.Type = &responseType
		acMessageEnvelope.Blob = []byte(retErr.Error())
		msgReply, err = proto.Marshal(acMessageEnvelope)
		if err != nil {
			//fmt.Fprintf(os.Stderr, "[!] HandleACMsg() -> Unmarshal():-2 ! %s\n", err.Error())
			return nil, acpbError(-2, "HandleACMsg().Marshal(): ", err)
		}
		//fmt.Fprintf(os.Stderr, "[!] HandleACMsg() -> Unmarshal():-1 ! %s\n", retErr.Error())
		return msgReply, retErr
	}

	switch MsgEnvp := acMessageEnvelope.GetType(); MsgEnvp {
	//switch responseType = acMessageEnvelope.GetType(); responseType {
	case ArseneCryptoMessage_AC_PK:
		//var responseType ArseneCryptoMessageAcMessageType
		//fmt.Printf("this is a Public Key Message\n")
		// TEST error condition
		pkMsgReply, err := HandleACPkMsg(acMessageEnvelope.GetBlob())
		/*
		   if err != nil {
		       return nil, acpbError(-1, "HandleACPkMsg(): ", err)
		   }
		*/

		// now let's pack it in the new message
		responseType = ArseneCryptoMessage_AC_PK
		acMessageEnvelope.Reset()
		acMessageEnvelope.Type = &responseType
		acMessageEnvelope.Blob = pkMsgReply

		// now return
		msgReply, merr := proto.Marshal(acMessageEnvelope)
		if merr != nil {
			return nil, acpbError(-3, "HandleACMsg(): ", err)
		}
		return msgReply, err
	case ArseneCryptoMessage_AC_KEX:
		// XXX TODO: need to clean KEX messages and CT messages too!!
		//var responseType ArseneCryptoMessageAcMessageType
		//fmt.Fprintf(os.Stderr, "this is a Key Exchange Message\n")

		kxMsgReply, err := HandleACKxMsg(acMessageEnvelope.GetBlob())

		// now let's pack it in the new message
		responseType = ArseneCryptoMessage_AC_KEX
		acMessageEnvelope.Reset()
		acMessageEnvelope.Type = &responseType
		acMessageEnvelope.Blob = kxMsgReply
		// now return
		msgReply, err := proto.Marshal(acMessageEnvelope)
		/*
		   acMessageKexMsg := &ac.AcPublicKeyMessageRequest{}
		   proto.Unmarshal(acMessageEnvelope.GetBlob(), acMessageKexMsg)
		*/
		return msgReply, err
	case ArseneCryptoMessage_AC_CRYPTO:
		//var responseType ArseneCryptoMessageAcMessageType
		fmt.Fprintf(os.Stderr, "this is a CipherText Message\n")
		ctMsgReply, err := HandleACCtMsg(acMessageEnvelope.GetBlob())

		// now let's pack it in the new message
		responseType = ArseneCryptoMessage_AC_CRYPTO
		acMessageEnvelope.Reset()
		acMessageEnvelope.Type = &responseType
		acMessageEnvelope.Blob = ctMsgReply
		// now return
		msgReply, err := proto.Marshal(acMessageEnvelope)
		return msgReply, err
	case ArseneCryptoMessage_AC_CTL:
		// control messages let's start with PING!
		ctlMsgReply, err := HandleACCtlMsg(acMessageEnvelope.GetBlob())

		// now let's pack it in the new message
		responseType = ArseneCryptoMessage_AC_CTL
		acMessageEnvelope.Reset()
		acMessageEnvelope.Type = &responseType
		acMessageEnvelope.Blob = ctlMsgReply
		// now return
		msgReply, err := proto.Marshal(acMessageEnvelope)
		return msgReply, err
	case ArseneCryptoMessage_AC_QUIT:
		// we go out!!
		ACrun = false
	default:
		fmt.Fprintf(os.Stderr, "this is a an unhandled (yet) type message\n")
	} /* end of switch.. */

	return
}
