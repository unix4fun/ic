package acpb

import (
	"fmt"
	"github.com/golang/protobuf/proto" // protobuf is now here.
	"github.com/unix4fun/ac/acutl"
	"os"
	"runtime"
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
	oPubKeys      []*AcPublicKey
	oHaveErrorMsg bool
}

var PKGENTests = []Test{
	// TEST #1 : OK
	{AcPublicKeyMessageRequest_PK_GEN,
		&AcPublicKeyMessageRequest{
			Nick:   proto.String("nick1"),
			Host:   proto.String("prout@hostname"),
			Server: proto.String("freenode.net"),
		}, AcPublicKeyMessageResponse_PKR_GEN, true, 0, nil, nil, false,
	},
	// TEST #2 : FAIL -1
	{AcPublicKeyMessageRequest_PK_GEN,
		&AcPublicKeyMessageRequest{
			Nick:   nil,
			Host:   proto.String("prout@hostname"),
			Server: proto.String("freenode.net"),
		}, AcPublicKeyMessageResponse_PKR_GEN, false, -1, nil, nil, true,
	},

	// TEST #3 : FAIL -1
	{AcPublicKeyMessageRequest_PK_GEN,
		&AcPublicKeyMessageRequest{
			Nick:   proto.String("mynick"),
			Host:   proto.String("eau@host.com"),
			Server: nil,
		}, AcPublicKeyMessageResponse_PKR_GEN, false, -1, nil, nil, true,
	},

	// TEST #4 : OK
	{AcPublicKeyMessageRequest_PK_GEN,
		&AcPublicKeyMessageRequest{
			Nick:   proto.String("eau"),
			Host:   proto.String("h2o@unix4funnnn.net"),
			Server: proto.String("freeenode.net"),
		}, AcPublicKeyMessageResponse_PKR_GEN, true, 0, nil, nil, false,
	},

	// TEST #4 : FAIL -1
	{AcPublicKeyMessageRequest_PK_GEN,
		&AcPublicKeyMessageRequest{
			Nick:   nil,
			Host:   nil,
			Server: nil,
		}, AcPublicKeyMessageResponse_PKR_GEN, false, -1, nil, nil, true,
	},
}

var PKADDTests = []Test{
	// TEST #1 : OK
	{AcPublicKeyMessageRequest_PK_ADD,
		&AcPublicKeyMessageRequest{
			Nick:   proto.String("nick1"),
			Host:   proto.String("prout@hostname"),
			Server: proto.String("freenode.net"),
			Blob:   []byte("DSix7zIaLXjaSrzBNkm3dtqdHqWLk2wnyVt/y+wNq01n5Avc6RaXdcrcDxAAAP//7okNxA=="),
		}, AcPublicKeyMessageResponse_PKR_ADD, true, 0, nil, nil, false,
	},

	// TEST #2 : Invalid base64 -2
	{AcPublicKeyMessageRequest_PK_ADD,
		&AcPublicKeyMessageRequest{
			Nick:   proto.String("nick3"),
			Host:   proto.String("prout@hostname"),
			Server: proto.String("freenode.net"),
			Blob:   []byte("DSix7zIaLXjaSrzBNkm3dtqdHqWLk2wnyVt/y+wNq01n5Avc6RaXdcrcDxAAAP//7okNxA"),
		}, AcPublicKeyMessageResponse_PKR_ADD, false, -2, nil, nil, true,
	},

	// TEST #3 : null blob -1
	{AcPublicKeyMessageRequest_PK_ADD,
		&AcPublicKeyMessageRequest{
			Nick:   proto.String("nick4"),
			Host:   proto.String("prout@hostname"),
			Server: proto.String("freenode.net"),
			Blob:   nil,
		}, AcPublicKeyMessageResponse_PKR_ADD, false, -1, nil, nil, true,
	},

	// TEST #4 : null nick
	{AcPublicKeyMessageRequest_PK_ADD,
		&AcPublicKeyMessageRequest{
			Nick:   nil,
			Host:   proto.String("prout@hostname"),
			Server: proto.String("freenode.net"),
			Blob:   []byte("DSix7zIaLXjaSrzBNkm3dtqdHqWLk2wnyVt/y+wNq01n5Avc6RaXdcrcDxAAAP//7okNxA=="),
		}, AcPublicKeyMessageResponse_PKR_ADD, false, -1, nil, nil, true,
	},

	// TEST #5 : null nick
	{AcPublicKeyMessageRequest_PK_ADD,
		&AcPublicKeyMessageRequest{
			Nick:   proto.String("nanother"),
			Host:   proto.String("prout@hostname"),
			Server: proto.String("freenode.net"),
			Blob:   []byte("AAAAAAAADSix7zIaLXjaSrzBNkm3dtqdHqWLk2wnyVt/y+wNq01n5Avc6RaXdcrcDxAAAP//7okNxAAAAAAAAAAAAAAAAA=="),
		}, AcPublicKeyMessageResponse_PKR_ADD, false, -2, nil, nil, true,
	},

	// TEST #6 : OK
	{AcPublicKeyMessageRequest_PK_ADD,
		&AcPublicKeyMessageRequest{
			Nick:   proto.String("nick1"),
			Host:   proto.String("prout@hostname"),
			Server: proto.String("freenode.net"),
			Blob:   []byte("DSix7zIaLXjaSrzBNkm3dtqdHqWLk2wnyVt/y+wNq01n5Avc6RaXdcrcDxAAAP//7okNxA=="),
		}, AcPublicKeyMessageResponse_PKR_ADD, true, 0, nil, nil, false,
	},

}// End of PKADD TESTs

var PKLISTTests = []Test{
	// TEST #1 : OK
	{AcPublicKeyMessageRequest_PK_LIST,
		&AcPublicKeyMessageRequest{
			Nick:   proto.String("nick1"),
			Server: proto.String("freenode.net"),
		}, AcPublicKeyMessageResponse_PKR_LIST, false, -2, nil, nil, true,
	},

	// TEST #2 : OK
	{AcPublicKeyMessageRequest_PK_LIST,
		&AcPublicKeyMessageRequest{
			Nick:   proto.String("nick2"),
			Server: nil,
		}, AcPublicKeyMessageResponse_PKR_LIST, false, -1, nil, nil, true,
	},
}

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
			t.Errorf("[%d] type exp: %v res: [%v]", i, v.oType, r.GetType())
		}
		// did it succeed or not
		if r.GetBada() != v.oBada {
			t.Errorf("[%d] exp: %t res: %t", i, v.oBada, r.GetBada())
		}
		// is it the expected error code?
		if r.GetErrorCode() != v.oErrorCode {
			t.Errorf("[%d] exp: %d res: %d", i, v.oErrorCode, r.GetErrorCode())
		}
	}
}

func oneTest(fn pkhandler, in *AcPublicKeyMessageRequest) (out *AcPublicKeyMessageResponse, err error) {
	out, err = fn(in)
	return
}

func TestPK(t *testing.T) {
	acutl.LogInit(os.Stderr)
	// TEST PKGEN
	fmt.Printf("\n== PKGEN TESTs ==\n")
	makeTests(PKGENTests, PKGEN_Handler, t)

	// TEST PKADD
	fmt.Printf("\n== PKADD TESTs ==\n")
	makeTests(PKADDTests, PKADD_Handler, t)

	// TEST PKLIST
	fmt.Printf("\n== PKLIST TESTs ==\n")
	makeTests(PKLISTTests, PKLIST_Handler, t)
}
