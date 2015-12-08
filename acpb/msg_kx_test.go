package acpb

import (
	"fmt"
	"github.com/golang/protobuf/proto" // protobuf is now here.
	"github.com/unix4fun/ac/acutl"
	"os"
	//"runtime"
	"github.com/unix4fun/ac/ackp"
	"testing"
)

type kxhandler func(*AcKeyExchangeMessageRequest) (acMsgResponse *AcKeyExchangeMessageResponse, err error)

type Test struct {
	// input
	inType AcKeyExchangeMessageRequestAcKXReqMsgType
	in     *AcKeyExchangeMessageRequest // input
	// Expected output
	oType AcKeyExchangeMessageResponseAcKXRespMsgType
	oBada         bool
	oErrorCode    int32
	oBlob         []byte
	oNonce          uint32
	oHaveErrorMsg bool
	//oType         AcPublicKeyMessageResponseAcPKRespMsgType
	//inType AcPublicKeyMessageRequestAcPKReqMsgType
	//in     *AcPublicKeyMessageRequest // input
	//oPubKeys      []*AcPublicKey // we just compare nick and server && public keys
	//oPubKeysLen   int            // number of pubkeys in the list!!
}

var KXPACKTests = []Test{
	// TEST #0 : OK
	{AcKeyExchangeMessageRequest_KX_PACK,
		&AcKeyExchangeMessageRequest{
			Channel: nil,
			Mynick: proto.String("toto"),
			Peernick: proto.String("bleh"),
			Server: proto.String("freenode.net"),
		}, AcKeyExchangeMessageResponse_KXR_PACK, false, -1, nil, nil, 0, false,
	},
	/*
	// TEST #1 : FAIL -1
	{AcPublicKeyMessageRequest_PK_GEN,
		&AcPublicKeyMessageRequest{
			Nick:   nil,
			Host:   proto.String("prout@hostname"),
			Server: proto.String("freenode.net"),
		}, AcPublicKeyMessageResponse_PKR_GEN, false, -1, nil, nil, 0, true,
	},

	// TEST #2 : FAIL -1
	{AcPublicKeyMessageRequest_PK_GEN,
		&AcPublicKeyMessageRequest{
			Nick:   proto.String("mynick"),
			Host:   proto.String("eau@host.com"),
			Server: nil,
		}, AcPublicKeyMessageResponse_PKR_GEN, false, -1, nil, nil, 0, true,
	},

	// TEST #3 : OK
	{AcPublicKeyMessageRequest_PK_GEN,
		&AcPublicKeyMessageRequest{
			Nick:   proto.String("eau"),
			Host:   nil,
			Server: proto.String("othernet.net"),
		}, AcPublicKeyMessageResponse_PKR_GEN, true, 0, nil, nil, 0, false,
	},

	// TEST #4 : FAIL -1
	{AcPublicKeyMessageRequest_PK_GEN,
		&AcPublicKeyMessageRequest{
			Nick:   nil,
			Host:   nil,
			Server: nil,
		}, AcPublicKeyMessageResponse_PKR_GEN, false, -1, nil, nil, 0, true,
	},
	*/
}

/*
 * TESTs needed
 * PKGEN -> PKR_GEN
 */

func makeTests(tests []Test, fn kxhandler, t *testing.T) {
	for i, v := range tests {
		reqType := v.inType
		v.in.Type = &reqType

		fmt.Printf("=> TEST %d <=\n", i)
		r, e := oneTest(fn, v.in)

		// are we expecting an error message
		if e != nil && v.oHaveErrorMsg == false {
			t.Errorf("[%d] Expected: %t Error: [%s]", i, v.oHaveErrorMsg, e.Error())
		}

		// type REPLY ?
		if r.GetType() != v.oType {
			t.Errorf("[%d] Type exp: %v res: [%v]", i, v.oType, r.GetType())
		}
		// did it succeed or not
		if r.GetBada() != v.oBada {
			t.Errorf("[%d] Bada exp: %t res: %t", i, v.oBada, r.GetBada())
		}
		// is it the expected error code?
		if r.GetErrorCode() != v.oErrorCode {
			t.Errorf("[%d] ErrorCode exp: %d res: %d", i, v.oErrorCode, r.GetErrorCode())
		}

	}
}

func oneTest(fn kxhandler, in *AcKeyExchangeMessageRequest) (out *AcKeyExchangeMessageResponse, err error) {
	out, err = fn(in)
	return
}

func TestKX(t *testing.T) {

	// init the Log
	acutl.InitDebugLog(os.Stderr)
	// init the key map for our tests..
	ackp.ACmap = ackp.NewPSKMap()

	// TEST KXPACK : pack key exchange
	fmt.Printf("\n== PKGEN TESTs ==\n")
	makeTests(KXPACKTests, KXPACK_Handler, t)

	// TEST PKADD : nick1 & nick2 stored too
	/*
	fmt.Printf("\n== PKADD TESTs ==\n")
	makeTests(PKADDTests, PKADD_Handler, t)

	// TEST PKLIST
	fmt.Printf("\n== PKLIST TESTs ==\n")
	makeTests(PKLISTTests, PKLIST_Handler, t)

	// TEST PKDEL
	fmt.Printf("\n== PKDEL TESTs ==\n")
	makeTests(PKDELTests, PKDEL_Handler, t)
	*/
}

/*
func TraceFunc2() string {
	pc := make([]uintptr, 10) // at least 1 entry needed
	runtime.Callers(2, pc)
	f := runtime.FuncForPC(pc[0])
	file, line := f.FileLine(pc[0])
	return fmt.Sprintf("[+] %s\n \\_ %s:%d\n", f.Name(), file, line)
}

func TraceFunc() *runtime.Func {
	pc := make([]uintptr, 10) // at least 1 entry needed
	runtime.Callers(2, pc)
	return runtime.FuncForPC(pc[0])
}

func TraceHdr(f *runtime.Func) string {
	file, line := f.FileLine(f.Entry())
	return fmt.Sprintf("[+] %s\n \\_ %s:%d\n", f.Name(), file, line)
}
*/
