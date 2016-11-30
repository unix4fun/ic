package icutl

import (
	"bytes"
	cr "crypto/rand"
	"math/rand"
	"testing"
)

type iotest struct {
	in  []byte // input
	out []byte // output
}

var tests = []iotest{
	{[]byte("A"), nil},
	{[]byte("A"), nil},
	{[]byte("F"), nil},
	{[]byte("F"), nil},
}

//
//
// COMPRESS/DECOMPRESS TESTS
//
//
func TestCompressDecompressData(t *testing.T) {

	// 1. first let's test with a known set of vectors including with EMPTY
	// datas etc..
	for i := 0; i < len(tests); i++ {
		o, err := CompressData(tests[i].in)
		if err != nil {
			t.Logf("CompressData() error\n")
			t.Fail()
		}

		oo, err := DecompressData(o)
		if err != nil {
			t.Logf("DecompressData() error\n")
			t.Fail()
		}

		if bytes.Equal(tests[i].in, oo) == false {
			t.Logf("not matching '%s' vs '%s'\n", tests[i].in, oo)
			t.Fail()
		}

	}

	// now with random data
	for i := 0; i < 1000; i++ {
		obfIn := make([]byte, rand.Intn(10000))
		cr.Read(obfIn)

		o, err := CompressData(obfIn)
		if err != nil {
			t.Logf("CompressData() error\n")
			t.Fail()
		}

		oo, err := DecompressData(o)
		if err != nil {
			t.Logf("DecompressData() error\n")
			t.Fail()
		}

		if bytes.Equal(obfIn, oo) == false {
			t.Logf("not matching 'len(%d)' vs 'len(%d)'\n", len(obfIn), len(oo))
			t.Fail()
		}
	}
}

func TestCompressDecompressDataError(t *testing.T) {
	o, err := CompressData(nil)
	if err == nil {
		t.Logf("CompressData() SHOULD error: %v [%d]\n", err, len(o))
		t.Fail()
	}

	oo, err := DecompressData(nil)
	if err == nil {
		t.Logf("DecompressData() SHOULD error: %v [%d]\n", err, len(oo))
		t.Fail()
	}
}

//
//
// BASE64 TESTS
//
//
