// +build go1.4
package acpb

import (
	//	"fmt"
	"github.com/golang/protobuf/proto" // protobuf is now here.
	"github.com/unix4fun/ac/ackp"
	//	"os"
	"github.com/unix4fun/ac/acutl"
	"time"
)

func CTLPING_Handler(acMessageCtlReq *AcControlMessageRequest) (acMsgResponse *AcControlMessageResponse, err error) {
	var responseType AcControlMessageResponseAcCTLRRespMsgType
	responseType = AcControlMessageResponse_CTLR_PONG
	timeStamp := acMessageCtlReq.GetTimestamp()

	acutl.DebugLog.Printf("(CALL) CTLPING timestamp: %d\n", timeStamp)

	if timeStamp <= 0 {
		retErr := &acutl.AcError{Value: -1, Msg: "CTLPING invalid timestamp", Err: nil}
		acMsgResponse = &AcControlMessageResponse{
			Type:      &responseType,
			Bada:      proto.Bool(false),
			ErrorCode: proto.Int32(-1),
		}
		acutl.DebugLog.Printf("(RET[!]) CTLPING -> (-1) ! %s\n", retErr.Error())
		return acMsgResponse, retErr
	}

	replyTime := time.Now().Unix()

	acMsgResponse = &AcControlMessageResponse{
		Type:      &responseType,
		Bada:      proto.Bool(true),
		ErrorCode: proto.Int32(0), // should be good enough for now... but better have a separate field with correct type..
		Timestamp: &replyTime,
	}
	acutl.DebugLog.Printf("(RET) CTLPING -> (0) ! PONG REPLIED. %d\n", replyTime)
	return acMsgResponse, nil
}

func CTLLOAD_Handler(acMessageCtlReq *AcControlMessageRequest) (acMsgResponse *AcControlMessageResponse, err error) {
	var responseType AcControlMessageResponseAcCTLRRespMsgType
	responseType = AcControlMessageResponse_CTLR_LOADCTX
	reqPassword := acMessageCtlReq.GetPassword()

	acutl.DebugLog.Printf("(CALL) LOADCTX '%s'\n", reqPassword)

	if len(reqPassword) == 0 {
		retErr := &acutl.AcError{Value: -1, Msg: "CTLLOAD_Handler().args(): empty password", Err: nil}
		acMsgResponse = &AcControlMessageResponse{
			Type:      &responseType,
			Bada:      proto.Bool(false),
			ErrorCode: proto.Int32(-1),
		}
		acutl.DebugLog.Printf("(RET[!]) LOADCTX -> (-1) File2Map failed\n")
		return acMsgResponse, retErr
	}

	ok, err := ackp.ACmap.File2Map(ackp.AcSaveFile, []byte(reqPassword))
	if err != nil || ok != true {
		retErr := &acutl.AcError{Value: -2, Msg: "CTLLOAD_Handler().args(outfile, keystr): 0 bytes", Err: nil}
		acMsgResponse = &AcControlMessageResponse{
			Type:      &responseType,
			Bada:      proto.Bool(false),
			ErrorCode: proto.Int32(-2),
		}
		acutl.DebugLog.Printf("(RET[!]) LOADCTX -> (-2) File2Map failed\n")
		return acMsgResponse, retErr
	}
	acMsgResponse = &AcControlMessageResponse{
		Type:      &responseType,
		Bada:      proto.Bool(true),
		ErrorCode: proto.Int32(0),
	}
	acutl.DebugLog.Printf("(RET) LOADCTX -> (0) ! '%s' opened\n", reqPassword)
	return acMsgResponse, nil
}

func CTLSAVE_Handler(acMessageCtlReq *AcControlMessageRequest) (acMsgResponse *AcControlMessageResponse, err error) {
	var responseType AcControlMessageResponseAcCTLRRespMsgType
	responseType = AcControlMessageResponse_CTLR_SAVECTX
	reqPassword := acMessageCtlReq.GetPassword()

	acutl.DebugLog.Printf("(CALL) SAVECTX '%s'\n", reqPassword)
	if len(reqPassword) == 0 {
		retErr := &acutl.AcError{Value: -1, Msg: "CTLSAVE_Handler().args(): empty password", Err: nil}
		acMsgResponse = &AcControlMessageResponse{
			Type:      &responseType,
			Bada:      proto.Bool(false),
			ErrorCode: proto.Int32(-1),
		}
		acutl.DebugLog.Printf("(RET[!]) SAVECTX -> (-1) Map2File failed\n")
		return acMsgResponse, retErr
	}

	//func (psk PSKMap) Map2FileBlob(outfilestr string, salt []byte, keystr []byte) (bool, error) {
	// TODO: we hardcode the save file
	ok, err := ackp.ACmap.Map2File(ackp.AcSaveFile, []byte(reqPassword))
	if err != nil || ok != true {
		retErr := &acutl.AcError{Value: -2, Msg: "CTLSAVE_Handler().args(outfile, salt, keystr): 0 bytes", Err: nil}
		acMsgResponse = &AcControlMessageResponse{
			Type:      &responseType,
			Bada:      proto.Bool(false),
			ErrorCode: proto.Int32(-2),
		}
		acutl.DebugLog.Printf("(RET[!]) SAVECTX -> (-2) Map2File failed\n")
		return acMsgResponse, retErr
	}
	acMsgResponse = &AcControlMessageResponse{
		Type:      &responseType,
		Bada:      proto.Bool(true),
		ErrorCode: proto.Int32(0),
	}
	acutl.DebugLog.Printf("(RET) SAVECTX -> (0) ! '%s' saved\n", reqPassword)
	return acMsgResponse, nil
}

//
//
// Handle Key Exchange MESSAGES..
//
//
func HandleACCtlMsg(msg []byte) (msgReply []byte, err error) {
	var acReplyCtlMsg *AcControlMessageResponse
	acutl.DebugLog.Printf("(CALL) HandleACCtlMsg()\n")

	// unpack the old message
	acMessageCtlReq := &AcControlMessageRequest{}
	err = proto.Unmarshal(msg, acMessageCtlReq)
	if err != nil {
		return nil, err
	}

	switch ctlMsg := acMessageCtlReq.GetType(); ctlMsg {
	case AcControlMessageRequest_CTL_PING:
		acReplyCtlMsg, err = CTLPING_Handler(acMessageCtlReq)
	case AcControlMessageRequest_CTL_LOADCTX:
		acReplyCtlMsg, err = CTLLOAD_Handler(acMessageCtlReq)
	case AcControlMessageRequest_CTL_SAVECTX:
		acReplyCtlMsg, err = CTLSAVE_Handler(acMessageCtlReq)
	default:
		err = &acutl.AcError{Value: -255, Msg: "HandleACCtlMsg(): unknown CTL request!", Err: nil}
		acutl.DebugLog.Printf("(RET[!]) HandleACCtlMsg(): unknown CTL request\n")
		return nil, err
	}

	msgReply, err = proto.Marshal(acReplyCtlMsg)
	acutl.DebugLog.Printf("(RET) HandleACCtlMsg():\n\tacReplyCtlMsg: %v\n\tmsgReply: %v\n\terr: %v\n", acReplyCtlMsg, msgReply, err)
	return msgReply, err
}
