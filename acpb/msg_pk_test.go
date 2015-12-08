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

type pkhandler func(*AcPublicKeyMessageRequest) (acMsgResponse *AcPublicKeyMessageResponse, err error)

type Test struct {
	// input
	inType AcPublicKeyMessageRequestAcPKReqMsgType
	in     *AcPublicKeyMessageRequest // input
	// Expected output
	oType         AcPublicKeyMessageResponseAcPKRespMsgType
	oBada         bool
	oErrorCode    int32
	oBlob         []byte
	oPubKeys      []*AcPublicKey // we just compare nick and server && public keys
	oPubKeysLen   int            // number of pubkeys in the list!!
	oHaveErrorMsg bool
}

var PKGENTests = []Test{
	// TEST #0 : OK
	{AcPublicKeyMessageRequest_PK_GEN,
		&AcPublicKeyMessageRequest{
			Nick:   proto.String("myself"),
			Host:   proto.String("prout@hostname"),
			Server: proto.String("freenode.net"),
		}, AcPublicKeyMessageResponse_PKR_GEN, true, 0, nil, nil, 0, false,
	},
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
}

var PKADDTests = []Test{
	// TEST #0 : OK
	{AcPublicKeyMessageRequest_PK_ADD,
		&AcPublicKeyMessageRequest{
			Nick:   proto.String("nick1"),
			Host:   proto.String("prout@hostname"),
			Server: proto.String("freenode.net"),
			Blob:   []byte("DSix7zIaLXjaSrzBNkm3dtqdHqWLk2wnyVt/y+wNq01n5Avc6RaXdcrcDxAAAP//7okNxA=="),
		}, AcPublicKeyMessageResponse_PKR_ADD, true, 0, nil, nil, 0, false,
	},

	// TEST #1 : FAIL -> Invalid base64 -2
	{AcPublicKeyMessageRequest_PK_ADD,
		&AcPublicKeyMessageRequest{
			Nick:   proto.String("nick3"),
			Host:   proto.String("prout@hostname"),
			Server: proto.String("freenode.net"),
			Blob:   []byte("DSix7zIaLXjaSrzBNkm3dtqdHqWLk2wnyVt/y+wNq01n5Avc6RaXdcrcDxAAAP//7okNxA"),
		}, AcPublicKeyMessageResponse_PKR_ADD, false, -2, nil, nil, 0, true,
	},

	// TEST #2 : FAIL -> null blob -1
	{AcPublicKeyMessageRequest_PK_ADD,
		&AcPublicKeyMessageRequest{
			Nick:   proto.String("nick4"),
			Host:   proto.String("prout@hostname"),
			Server: proto.String("freenode.net"),
			Blob:   nil,
		}, AcPublicKeyMessageResponse_PKR_ADD, false, -1, nil, nil, 0, true,
	},

	// TEST #3 : FAIL -> null nick
	{AcPublicKeyMessageRequest_PK_ADD,
		&AcPublicKeyMessageRequest{
			Nick:   nil,
			Host:   proto.String("prout@hostname"),
			Server: proto.String("freenode.net"),
			Blob:   []byte("DSix7zIaLXjaSrzBNkm3dtqdHqWLk2wnyVt/y+wNq01n5Avc6RaXdcrcDxAAAP//7okNxA=="),
		}, AcPublicKeyMessageResponse_PKR_ADD, false, -1, nil, nil, 0, true,
	},

	// TEST #4 : FAIL -> null nick
	{AcPublicKeyMessageRequest_PK_ADD,
		&AcPublicKeyMessageRequest{
			Nick:   proto.String("nanother"),
			Host:   proto.String("prout@hostname"),
			Server: proto.String("freenode.net"),
			Blob:   []byte("AAAAAAAADSix7zIaLXjaSrzBNkm3dtqdHqWLk2wnyVt/y+wNq01n5Avc6RaXdcrcDxAAAP//7okNxAAAAAAAAAAAAAAAAA=="),
		}, AcPublicKeyMessageResponse_PKR_ADD, false, -2, nil, nil, 0, true,
	},

	// TEST #5 : OK
	{AcPublicKeyMessageRequest_PK_ADD,
		&AcPublicKeyMessageRequest{
			Nick:   proto.String("nick2"),
			Host:   proto.String("prout@hostname"),
			Server: proto.String("freenode.net"),
			Blob:   []byte("DSix7zIaLXjaSrzBNkm3dtqdHqWLk2wnyVt/y+wNq01n5Avc6RaXdcrcDxAAAP//7okNxA=="),
		}, AcPublicKeyMessageResponse_PKR_ADD, true, 0, nil, nil, 0, false,
	},
} // End of PKADD TESTs

// TODO we need to create an array of public keys to test again
// or the length in case of a list to not test again the whole list..

var acPubkeyArrayTest1 = []*AcPublicKey{
	&AcPublicKey{
		Nick:      proto.String("nick1"),
		Pubkey:    proto.String("DSix7zIaLXjaSrzBNkm3dtqdHqWLk2wnyVt/y+wNq01n5Avc6RaXdcrcDxAAAP//7okNxA=="),
		Host:      proto.String("prout@hostname"),
		Server:    proto.String("freenode.net"),
		Haspriv:   proto.Bool(false),
		Fp:        nil,
		Timestamp: proto.Int64(0),
	},
}

var PKLISTTests = []Test{
	// TEST #0 : OK / But no such keys
	{AcPublicKeyMessageRequest_PK_LIST,
		&AcPublicKeyMessageRequest{
			Nick:   proto.String("jdskjdskj"),
			Server: proto.String("freenode.net"),
		}, AcPublicKeyMessageResponse_PKR_LIST, false, -2, nil, nil, 0, true,
	},

	// TEST #1 : OK / key exists
	{AcPublicKeyMessageRequest_PK_LIST,
		&AcPublicKeyMessageRequest{
			Nick:   proto.String("nick1"),
			Server: proto.String("freenode.net"),
		}, AcPublicKeyMessageResponse_PKR_LIST, true, 0, nil, acPubkeyArrayTest1, 1, false,
	},

	// TEST #2 : FAIL -> -1
	{AcPublicKeyMessageRequest_PK_LIST,
		&AcPublicKeyMessageRequest{
			Nick:   proto.String("nick2"),
			Server: nil,
		}, AcPublicKeyMessageResponse_PKR_LIST, false, -1, nil, nil, 0, true,
	},

	// TEST #3 : OK -> all keys...
	{AcPublicKeyMessageRequest_PK_LIST,
		&AcPublicKeyMessageRequest{
			Nick:   nil,
			Server: proto.String("freenode.net"),
		}, AcPublicKeyMessageResponse_PKR_LIST, true, 0, nil, nil, 4, false,
	},

	// TEST #4 : OK -> all keys... but wrong server nothing found!
	{AcPublicKeyMessageRequest_PK_LIST,
		&AcPublicKeyMessageRequest{
			Nick:   nil,
			Server: proto.String("net"),
		}, AcPublicKeyMessageResponse_PKR_LIST, false, -2, nil, nil, 0, true,
	},
}

// PKDEL message simples functionnal tests
var PKDELTests = []Test{
	// TEST #0: description
	{AcPublicKeyMessageRequest_PK_DEL,
		&AcPublicKeyMessageRequest{
			Nick:   proto.String("nick1"),
			Server: proto.String("freenode.net"),
		}, AcPublicKeyMessageResponse_PKR_DEL, true, 0, nil, nil, 0, false,
	},
	// TEST #1: description it was already deleted..
	{AcPublicKeyMessageRequest_PK_DEL,
		&AcPublicKeyMessageRequest{
			Nick:   proto.String("nick1"),
			Server: proto.String("freenode.net"),
		}, AcPublicKeyMessageResponse_PKR_DEL, false, -1, nil, nil, 0, true,
	},

	// TEST #2: description it was already deleted..
	{AcPublicKeyMessageRequest_PK_DEL,
		&AcPublicKeyMessageRequest{
			Nick:   proto.String("nick1"),
			Server: proto.String("ode.net"),
		}, AcPublicKeyMessageResponse_PKR_DEL, false, -1, nil, nil, 0, true,
	},
	// TEST #3: description it was already deleted..
	{AcPublicKeyMessageRequest_PK_DEL,
		&AcPublicKeyMessageRequest{
			Nick:   nil,
			Server: proto.String("ode.net"),
		}, AcPublicKeyMessageResponse_PKR_DEL, false, -1, nil, nil, 0, true,
	},
	// TEST #4: description it was already deleted..
	{AcPublicKeyMessageRequest_PK_DEL,
		&AcPublicKeyMessageRequest{
			Nick:   nil,
			Server: nil,
		}, AcPublicKeyMessageResponse_PKR_DEL, false, -1, nil, nil, 0, true,
	},
	// TEST #5: description it was already deleted..
	{AcPublicKeyMessageRequest_PK_DEL,
		&AcPublicKeyMessageRequest{
			Nick:   proto.String("nick1"),
			Server: nil,
		}, AcPublicKeyMessageResponse_PKR_DEL, false, -1, nil, nil, 0, true,
	},
	// TEST #6: nick2 regular delete
	{AcPublicKeyMessageRequest_PK_DEL,
		&AcPublicKeyMessageRequest{
			Nick:   proto.String("nick2"),
			Server: proto.String("freenode.net"),
		}, AcPublicKeyMessageResponse_PKR_DEL, true, 0, nil, nil, 0, false,
	},
}

/*
 * TESTs needed
 * PKGEN -> PKR_GEN
 */

func makeTests(tests []Test, fn pkhandler, t *testing.T) {
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

		// Public keys test.. if they have to run..
		if reqType == AcPublicKeyMessageRequest_PK_LIST {
			pubKeys := r.GetPublicKeys()
			//fmt.Printf("PUBKEYS: %v\n", pubKeys)
			numPubKeys := len(pubKeys)

			if numPubKeys != v.oPubKeysLen {
				t.Errorf("[%d] Number of Keys exp: %d res: %d", i, v.oPubKeysLen, numPubKeys)
			} else {
				// XXX TODO: test public keys content to see if it's what was expected
			}
		}

	}
}

func oneTest(fn pkhandler, in *AcPublicKeyMessageRequest) (out *AcPublicKeyMessageResponse, err error) {
	out, err = fn(in)
	return
}

func TestPK(t *testing.T) {

	// init the Log
	acutl.InitDebugLog(os.Stderr)
	// init the key map for our tests..
	ackp.ACmap = ackp.NewPSKMap()

	// TEST PKGEN : myself & eau stored
	fmt.Printf("\n== PKGEN TESTs ==\n")
	makeTests(PKGENTests, PKGEN_Handler, t)

	// TEST PKADD : nick1 & nick2 stored too
	fmt.Printf("\n== PKADD TESTs ==\n")
	makeTests(PKADDTests, PKADD_Handler, t)

	// TEST PKLIST
	fmt.Printf("\n== PKLIST TESTs ==\n")
	makeTests(PKLISTTests, PKLIST_Handler, t)

	// TEST PKDEL
	fmt.Printf("\n== PKDEL TESTs ==\n")
	makeTests(PKDELTests, PKDEL_Handler, t)
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
