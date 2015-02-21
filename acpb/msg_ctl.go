// +build go1.4
package acpb

import (
	"fmt"
	"github.com/golang/protobuf/proto" // protobuf is now here.
	"os"
	"time"
)

func CTLPING_Handler(acMessageCtlReq *AcControlMessageRequest) (acMsgResponse *AcControlMessageResponse, err error) {
	var responseType AcControlMessageResponseAcCTLRRespMsgType
	responseType = AcControlMessageResponse_CTLR_PONG
	timeStamp := acMessageCtlReq.GetTimestamp()

	fmt.Fprintf(os.Stderr, "[+] CTLPING timestamp: %d\n", timeStamp)

	if timeStamp <= 0 {
		retErr := acpbError(-1, "CTLPING invalid timestamp", nil)
		acMsgResponse = &AcControlMessageResponse{
			Type:      &responseType,
			Bada:      proto.Bool(false),
			ErrorCode: proto.Int32(-1),
		}
		fmt.Fprintf(os.Stderr, "[!] CTLPING -> (R) -1 ! %s\n", retErr.Error())
		return acMsgResponse, retErr
	}

	replyTime := time.Now().Unix()

	//func CreateACMessage(context * ACMsgContext, msg, myNick []byte) (out []byte, err error) {
	acMsgResponse = &AcControlMessageResponse{
		Type:      &responseType,
		Bada:      proto.Bool(true),
		ErrorCode: proto.Int32(0), // should be good enough for now... but better have a separate field with correct type..
		Timestamp: &replyTime,
	}
	fmt.Fprintf(os.Stderr, "[+] CTLPING -> (R) 0 ! PONG REPLIED. %d\n", replyTime)
	return acMsgResponse, nil
}

func CTLLOAD_Handler(acMessageCtlReq *AcControlMessageRequest) (acMsgResponse *AcControlMessageResponse, err error) {
	var responseType AcControlMessageResponseAcCTLRRespMsgType
	responseType = AcControlMessageResponse_CTLR_LOADCTX
	reqFilename := acMessageCtlReq.GetFilename()

	fmt.Fprintf(os.Stderr, "[+] LOADCTX '%s'\n", reqFilename)

	ok, err := ACmap.File2Map(reqFilename, []byte("proutprout"), []byte("proutkey"))
	if err != nil || ok != false {
		retErr := acpbError(-1, "CTLLOAD_Handler().args(outfile, salt, keystr): 0 bytes", nil)
		acMsgResponse = &AcControlMessageResponse{
			Type:      &responseType,
			Bada:      proto.Bool(false),
			ErrorCode: proto.Int32(-1),
		}
		return acMsgResponse, retErr
	}
	acMsgResponse = &AcControlMessageResponse{
		Type:      &responseType,
		Bada:      proto.Bool(true),
		ErrorCode: proto.Int32(0),
	}
	fmt.Fprintf(os.Stderr, "[+] LOADCTX -> (R) 0 ! '%s' opened\n", reqFilename)
	return acMsgResponse, nil
}

func CTLSAVE_Handler(acMessageCtlReq *AcControlMessageRequest) (acMsgResponse *AcControlMessageResponse, err error) {
	var responseType AcControlMessageResponseAcCTLRRespMsgType
	responseType = AcControlMessageResponse_CTLR_SAVECTX
	reqFilename := acMessageCtlReq.GetFilename()

	fmt.Fprintf(os.Stderr, "[+] SAVECTX '%s'\n", reqFilename)

	//func (psk PSKMap) Map2FileBlob(outfilestr string, salt []byte, keystr []byte) (bool, error) {
	ok, err := ACmap.Map2File(reqFilename, []byte("proutprout"), []byte("proutkey"))
	if err != nil || ok != false {
		retErr := acpbError(-1, "CTLSAVE_Handler().args(outfile, salt, keystr): 0 bytes", nil)
		acMsgResponse = &AcControlMessageResponse{
			Type:      &responseType,
			Bada:      proto.Bool(false),
			ErrorCode: proto.Int32(-1),
		}
		return acMsgResponse, retErr
	}
	acMsgResponse = &AcControlMessageResponse{
		Type:      &responseType,
		Bada:      proto.Bool(true),
		ErrorCode: proto.Int32(0),
	}
	fmt.Fprintf(os.Stderr, "[+] SAVECTX -> (R) 0 ! '%s' saved\n", reqFilename)
	return acMsgResponse, nil
}

//
//
// Handle Key Exchange MESSAGES..
//
//
func HandleACCtlMsg(msg []byte) (msgReply []byte, err error) {
	var acReplyCtlMsg *AcControlMessageResponse
	fmt.Fprintf(os.Stderr, "HandleACPkMsg()\n")

	// unpack the old message
	acMessageCtlReq := &AcControlMessageRequest{}
	proto.Unmarshal(msg, acMessageCtlReq)

	switch ctlMsg := acMessageCtlReq.GetType(); ctlMsg {
	case AcControlMessageRequest_CTL_PING:
		fmt.Fprintf(os.Stderr, "PING CTL Message:!\n")
		// TODO we don't handle errors correctly yet...
		acReplyCtlMsg, err = CTLPING_Handler(acMessageCtlReq)
	case AcControlMessageRequest_CTL_LOADCTX:
		fmt.Fprintf(os.Stderr, "LOADCTX CTL Message:!\n")
		// TODO we don't handle errors correctly yet...
		acReplyCtlMsg, err = CTLLOAD_Handler(acMessageCtlReq)
	case AcControlMessageRequest_CTL_SAVECTX:
		fmt.Fprintf(os.Stderr, "SAVECTX CTL KEY Message:!\n")
		// TODO we don't handle errors correctly yet...
		acReplyCtlMsg, err = CTLSAVE_Handler(acMessageCtlReq)
	default:
		fmt.Fprintf(os.Stderr, "UNKNOWN Message: WTF?!?!\n")
		// TODO need to send a valid reponse with error -255
	}

	msgReply, err = proto.Marshal(acReplyCtlMsg)
	return msgReply, err
}
