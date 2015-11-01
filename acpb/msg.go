// +build go1.4
package acpb

import (
	//"fmt"
	"github.com/golang/protobuf/proto" // protobuf is now here.
	"github.com/unix4fun/ac/ackp"
	//"os"
	"errors"
	"github.com/unix4fun/ac/acutl"
)

//var ACmap ackp.PSKMap = ackp.ACmap
//var ACrun bool = ackp.ACrun

func ACEnvelopePack(responseType ArseneCryptoMessageAcMessageType, msg []byte, err error) (msgReply []byte, rerr error) {
	var acMessageEnvelope *ArseneCryptoMessage
	acutl.DebugLog.Printf("(CALL) ACEnvelopePack(%+v, %v, %v)", responseType, msg, err)

	if msg == nil {
		acMessageEnvelope = &ArseneCryptoMessage{
			Type: &responseType,
			Blob: []byte(err.Error()),
		}
	} else {
		acMessageEnvelope = &ArseneCryptoMessage{
			Type: &responseType,
			Blob: []byte(msg),
		}
	}
	msgReply, rerr = proto.Marshal(acMessageEnvelope)
	acutl.DebugLog.Printf("(RET) ACEnvelopePack() => msgReply: %+v err: %v", msgReply, rerr)
	return
}

// this function will reply on the socket directly..
// reply a packed ArseneCryptoMessage message to be sent by calling function.
// HANDLE ARSENE CRYPTO MESSAGES
func HandleACMsg(msg []byte) (msgReply []byte, err error) {
	//var responseType ArseneCryptoMessageAcMessageType
	acutl.DebugLog.Printf("(CALL) HandleACMsg(%v)", msg)

	// this is the beginning of the envelope response packet
	acMessageEnvelope := &ArseneCryptoMessage{}
	err = proto.Unmarshal(msg, acMessageEnvelope)
	if err != nil {
		acutl.DebugLog.Printf("(RET[!])\n\tHandleACMsg: -1 => %s", err.Error())
		return ACEnvelopePack(ArseneCryptoMessage_AC_ERROR, nil, err)
	}

	switch MsgEnvp := acMessageEnvelope.GetType(); MsgEnvp {
	//switch responseType = acMessageEnvelope.GetType(); responseType {
	case ArseneCryptoMessage_AC_PK:
		// TEST error condition
		pkMsgReply, err := HandleACPkMsg(acMessageEnvelope.GetBlob())
		if err != nil {
			acutl.DebugLog.Printf("(RET[!])\n\tMSG: %v ERR: %v", pkMsgReply, err)
			//return nil, err
			return ACEnvelopePack(ArseneCryptoMessage_AC_ERROR, nil, err)
			//       return nil, acpbError(-1, "HandleACPkMsg(): ", err)
		}

		return ACEnvelopePack(ArseneCryptoMessage_AC_PK, pkMsgReply, nil)

	case ArseneCryptoMessage_AC_KEX:
		// XXX TODO: need to clean KEX messages and CT messages too!!
		//var responseType ArseneCryptoMessageAcMessageType
		//fmt.Fprintf(os.Stderr, "this is a Key Exchange Message\n")

		kxMsgReply, err := HandleACKxMsg(acMessageEnvelope.GetBlob())
		if err != nil {
			//fmt.Fprintf(os.Stderr, "MSG: %v ERR: %v\n", kxMsgReply, err)
			acutl.DebugLog.Printf("(RET[!])\n\tMSG: %v ERR: %v", kxMsgReply, err)
			//return nil, err
			return ACEnvelopePack(ArseneCryptoMessage_AC_ERROR, nil, err)
		}

		return ACEnvelopePack(ArseneCryptoMessage_AC_KEX, kxMsgReply, nil)
	case ArseneCryptoMessage_AC_CRYPTO:
		//var responseType ArseneCryptoMessageAcMessageType
		//fmt.Fprintf(os.Stderr, "this is a CipherText Message\n")
		ctMsgReply, err := HandleACCtMsg(acMessageEnvelope.GetBlob())
		if err != nil {
			//fmt.Fprintf(os.Stderr, "MSG: %v ERR: %v\n", ctMsgReply, err)
			acutl.DebugLog.Printf("(RET[!])\n\tMSG: %v ERR: %v", ctMsgReply, err)
			//return nil, err
			return ACEnvelopePack(ArseneCryptoMessage_AC_ERROR, nil, err)
		}

		return ACEnvelopePack(ArseneCryptoMessage_AC_CRYPTO, ctMsgReply, nil)
	case ArseneCryptoMessage_AC_CTL:
		// control messages let's start with PING!
		ctlMsgReply, err := HandleACCtlMsg(acMessageEnvelope.GetBlob())
		if err != nil {
			acutl.DebugLog.Printf("(RET[!])\n\tMSG: %v ERR: %v", ctlMsgReply, err)
			//return nil, err
			return ACEnvelopePack(ArseneCryptoMessage_AC_ERROR, nil, err)
		}

		return ACEnvelopePack(ArseneCryptoMessage_AC_CTL, ctlMsgReply, nil)
	case ArseneCryptoMessage_AC_QUIT:
		// we go out!!
		ackp.ACrun = false
		return ACEnvelopePack(ArseneCryptoMessage_AC_QUIT, nil, errors.New("QUITTING"))
	default:
		err = &acutl.AcError{Value: -255, Msg: "Invalid/Unhandled Message Envelope", Err: nil}
		acutl.DebugLog.Printf("(RET[!])\n\tUNHANDLED\n")
		return ACEnvelopePack(ArseneCryptoMessage_AC_ERROR, nil, err)
	} /* end of switch.. */
	return
}
