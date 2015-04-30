package acpb

import (
	"fmt"
	"testing"
	"github.com/golang/protobuf/proto" // protobuf is now here.
	"github.com/unix4fun/ac/ackp"
)

/*
 * TESTs needed
 * PKGEN -> PKR_GEN
 */
//
// TEST PKGEN VALID
//
func TestPKGENMessage001(t *testing.T) {
	var reqType AcPublicKeyMessageRequestAcPKReqMsgType
	// if i send a valid request
	reqType = AcPublicKeyMessageRequest_PK_GEN
	fmt.Printf("=> TestPKGENMEssage001\n")

	// we need the context to be here...
	ackp.ACmap = make(ackp.PSKMap)

	// some infos..
	NickTest_1 := string("prout")
	HostTest_1 := string("eau@host.com")
	ServerTest_1 := string("irc.freenode.net")

	// test1: valid
	acMessagePkReq := &AcPublicKeyMessageRequest{
		Type:   &reqType,
		Nick:   proto.String(NickTest_1),
		Host:   proto.String(HostTest_1),
		Server: proto.String(ServerTest_1),
	}

	acMessagePkResp, err := PKGEN_Handler(acMessagePkReq)
	if err != nil {
		t.Errorf("No error this should be a valid message, but: %v\n", err)
		t.Errorf("Req: %v\n", acMessagePkReq)
		t.Errorf("Resp: %v\n", acMessagePkResp)
	}
	switch respType := acMessagePkResp.GetType(); respType {
	case AcPublicKeyMessageResponse_PKR_GEN:
		switch acMessagePkResp.GetBada() {
			case true:
			case false:
				t.Errorf("False when it should be true this is a working request!")
				t.Errorf("Req: %v\n", acMessagePkReq)
				t.Errorf("Resp: %v\n", acMessagePkResp)
		}
		switch acMessagePkResp.GetErrorCode() {
			case 0:
			default:
				t.Errorf("Error code is wrong")
				t.Errorf("Req: %v\n", acMessagePkReq)
				t.Errorf("Resp: %v\n", acMessagePkResp)
		}
	default:
		t.Errorf("Wrong Response Type : %d, expected: %d\n", respType, AcPublicKeyMessageResponse_PKR_GEN)
		t.Errorf("Req: %v\n", acMessagePkReq)
		t.Errorf("Resp: %v\n", acMessagePkResp)
	} // end of switch
}

//
// TEST PKGEN INVALID / nick: nil
//
func TestPKGENMessage002(t *testing.T) {
	var reqType AcPublicKeyMessageRequestAcPKReqMsgType
	// if i send a valid request
	reqType = AcPublicKeyMessageRequest_PK_GEN

	fmt.Printf("=> TestPKGENMEssage002\n")

	//    NickTest_1 := string("prout")
	HostTest_1 := string("eau@host.com")
	ServerTest_1 := string("irc.freenode.net")

	//fmt.Printf("TestPKGEN!\n")
	// test1: valid
	acMessagePkReq := &AcPublicKeyMessageRequest{
		Type:   &reqType,
		Nick:   nil,
		Host:   &HostTest_1,
		Server: &ServerTest_1,
	}

	acMessagePkResp, _ := PKGEN_Handler(acMessagePkReq)
	fmt.Printf("Type: %d\n", acMessagePkResp.GetType())
	switch respType := acMessagePkResp.GetType(); respType {
	case AcPublicKeyMessageResponse_PKR_GEN:
		switch respBada := acMessagePkResp.GetBada(); respBada {
		case true:
			t.Errorf("TestPKGEN_Handler2>Wrong Return Bool : %d\n", acMessagePkResp.GetErrorCode())
		case false:
		default:
			t.Errorf("TestPKGEN_Handler2>Wrong Return Bool\n")
		}
	default:
		t.Errorf("Wrong Type Returned: %d, expected: %d\n", respType, AcPublicKeyMessageResponse_PKR_GEN)
	} // end of switch
}

func TestPKGENMessage003(t *testing.T) {
	var reqType AcPublicKeyMessageRequestAcPKReqMsgType
	// if i send a valid request
	reqType = AcPublicKeyMessageRequest_PK_GEN

	NickTest_1 := string("prout")
	//HostTest_1 := string("eau@host.com")
	ServerTest_1 := string("irc.freenode.net")

	//fmt.Printf("TestPKGEN!\n")
	// test1: valid
	acMessagePkReq := &AcPublicKeyMessageRequest{
		Type:   &reqType,
		Nick:   &NickTest_1,
		Host:   nil,
		Server: &ServerTest_1,
	}

	acMessagePkResp, _ := PKGEN_Handler(acMessagePkReq)
	fmt.Printf("Type: %d\n", acMessagePkResp.GetType())
	switch respType := acMessagePkResp.GetType(); respType {
	case AcPublicKeyMessageResponse_PKR_GEN:
		switch respBada := acMessagePkResp.GetBada(); respBada {
		case true:
		case false:
			t.Errorf("TestPKGEN_Handler2>Wrong Return Bool : %d\n", acMessagePkResp.GetErrorCode())
		default:
			t.Errorf("TestPKGEN_Handler2>Wrong Return Bool\n")
		}
	default:
		t.Errorf("Wrong Type Returned: %d, expected: %d\n", respType, AcPublicKeyMessageResponse_PKR_GEN)
	} // end of switch
}

/*
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
*/
