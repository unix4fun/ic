package acpb

import (
	"fmt"
	//    "log"
	//    "net"
	"testing"
	//    "time"
	//    "crypto/rand"
	//    "arsene/ac/proto"
	//    "code.google.com/p/goprotobuf/proto"
	"github.com/unix4fun/ac/acpb"
)

//
// TEST PKGEN VALID
//
func TestPKGEN_Handler1(t *testing.T) {
	var reqType acpb.AcPublicKeyMessageRequestAcPKReqMsgType
	// if i send a valid request
	reqType = acpb.AcPublicKeyMessageRequest_PK_GEN

	NickTest_1 := string("prout")
	HostTest_1 := string("eau@host.com")
	ServerTest_1 := string("irc.freenode.net")

	//fmt.Printf("TestPKGEN!\n")
	// test1: valid
	acMessagePkReq := &acpb.AcPublicKeyMessageRequest{
		Type:   &reqType,
		Nick:   &NickTest_1,
		Host:   &HostTest_1,
		Server: &ServerTest_1,
	}

	acMessagePkResp, _ := acpb.PKGEN_Handler(acMessagePkReq)
	fmt.Printf("Type: %d\n", acMessagePkResp.GetType())
	switch respType := acMessagePkResp.GetType(); respType {
	case acpb.AcPublicKeyMessageResponse_PKR_GEN:
	default:
		t.Errorf("Wrong Type Returned: %d, expected: %d\n", respType, acpb.AcPublicKeyMessageResponse_PKR_GEN)
	} // end of switch
}

//
// TEST PKGEN INVALID / nick: nil
//
func TestPKGEN_Handler2(t *testing.T) {
	var reqType acpb.AcPublicKeyMessageRequestAcPKReqMsgType
	// if i send a valid request
	reqType = acpb.AcPublicKeyMessageRequest_PK_GEN

	//    NickTest_1 := string("prout")
	HostTest_1 := string("eau@host.com")
	ServerTest_1 := string("irc.freenode.net")

	//fmt.Printf("TestPKGEN!\n")
	// test1: valid
	acMessagePkReq := &acpb.AcPublicKeyMessageRequest{
		Type:   &reqType,
		Nick:   nil,
		Host:   &HostTest_1,
		Server: &ServerTest_1,
	}

	acMessagePkResp, _ := acpb.PKGEN_Handler(acMessagePkReq)
	fmt.Printf("Type: %d\n", acMessagePkResp.GetType())
	switch respType := acMessagePkResp.GetType(); respType {
	case acpb.AcPublicKeyMessageResponse_PKR_GEN:
		switch respBada := acMessagePkResp.GetBada(); respBada {
		case true:
		case false:
			t.Errorf("TestPKGEN_Handler2>Wrong Return Bool : %d\n", acMessagePkResp.GetErrorCode())
		default:
			t.Errorf("TestPKGEN_Handler2>Wrong Return Bool\n")
		}
	default:
		t.Errorf("Wrong Type Returned: %d, expected: %d\n", respType, acpb.AcPublicKeyMessageResponse_PKR_GEN)
	} // end of switch
}

func TestPKGEN_Handler3(t *testing.T) {
	var reqType acpb.AcPublicKeyMessageRequestAcPKReqMsgType
	// if i send a valid request
	reqType = acpb.AcPublicKeyMessageRequest_PK_GEN

	NickTest_1 := string("prout")
	//HostTest_1 := string("eau@host.com")
	ServerTest_1 := string("irc.freenode.net")

	//fmt.Printf("TestPKGEN!\n")
	// test1: valid
	acMessagePkReq := &acpb.AcPublicKeyMessageRequest{
		Type:   &reqType,
		Nick:   &NickTest_1,
		Host:   nil,
		Server: &ServerTest_1,
	}

	acMessagePkResp, _ := acpb.PKGEN_Handler(acMessagePkReq)
	fmt.Printf("Type: %d\n", acMessagePkResp.GetType())
	switch respType := acMessagePkResp.GetType(); respType {
	case acpb.AcPublicKeyMessageResponse_PKR_GEN:
		switch respBada := acMessagePkResp.GetBada(); respBada {
		case true:
		case false:
			t.Errorf("TestPKGEN_Handler2>Wrong Return Bool : %d\n", acMessagePkResp.GetErrorCode())
		default:
			t.Errorf("TestPKGEN_Handler2>Wrong Return Bool\n")
		}
	default:
		t.Errorf("Wrong Type Returned: %d, expected: %d\n", respType, acpb.AcPublicKeyMessageResponse_PKR_GEN)
	} // end of switch
}

func PROUTTetPKGEN_Handler(t *testing.T) {
	var PKReq []*acpb.AcPublicKeyMessageRequest
	var reqType acpb.AcPublicKeyMessageRequestAcPKReqMsgType
	// if i send a valid request
	reqType = acpb.AcPublicKeyMessageRequest_PK_GEN

	NickTest_1 := string("prout")
	HostTest_1 := string("eau@host.com")
	ServerTest_1 := string("irc.freenode.net")

	fmt.Printf("TestPKGEN!\n")

	// test1: valid
	acMessagePkReq := &acpb.AcPublicKeyMessageRequest{
		Type:   &reqType,
		Nick:   &NickTest_1,
		Host:   &HostTest_1,
		Server: &ServerTest_1,
	}
	PKReq = append(PKReq, acMessagePkReq)

	// test2: invalid, nick is nil, should get an error!
	acMessagePkReq = &acpb.AcPublicKeyMessageRequest{
		Type:   &reqType,
		Nick:   nil,
		Host:   &HostTest_1,
		Server: &ServerTest_1,
	}
	PKReq = append(PKReq, acMessagePkReq)

	for i, v := range PKReq {
		fmt.Printf("PKReq[%d] @ %p\n", i, v)
		acMessagePkResp, _ := acpb.PKGEN_Handler(v)
		fmt.Printf("Type: %d\n", acMessagePkResp.GetType())
		switch respType := acMessagePkResp.GetType(); respType {
		case acpb.AcPublicKeyMessageResponse_PKR_GEN:
		default:
			t.Errorf("Wrong Type Returned: %d, expected: %d\n", respType, acpb.AcPublicKeyMessageResponse_PKR_GEN)
		} // end of switch
	} // end of for()
}
