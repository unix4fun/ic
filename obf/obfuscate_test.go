package obf

import (
	"crypto/rand"
	"testing"
)

//  0x55        0x55
// [0101 0101] [0101 0101]

type iotest struct {
	in      []byte // input
	out     []byte // output
	mask_lo byte
	mask_hi byte
}

var tests = []iotest{
	{[]byte("A"), nil, 0x55, 0x55},
	{[]byte("A"), nil, 0x05, 0xf5},
	{[]byte("F"), nil, 0xf5, 0x05},
	{[]byte("F"), nil, 0xff, 0x00},
}

func TestObfuscateByte(t *testing.T) {
	for i := 0; i < len(tests); i++ {
		obfOut, err := ObfuscateByte(tests[i].in, tests[i].mask_hi, tests[i].mask_lo)
		if err != nil {
			t.Logf("ObfuscateByte error\n")
			t.Fail()
		}

		outIn, err := DeobfuscateByte(obfOut, tests[i].mask_hi, tests[i].mask_lo)
		if err != nil {
			t.Logf("DeObfuscateByte error\n")
			t.Fail()
		}

		if tests[i].in[0] != outIn[0] {
			t.Logf("matching error %02x vs %02x\n", tests[i].in, outIn[0])
			t.Fail()
		}
	}

	for i := 0; i < 100000; i++ {
		obfIn := make([]byte, 1)
		rand.Read(obfIn)

		obfOut, err := ObfuscateByte(obfIn, 0x55, 0x55)
		if err != nil {
			t.Logf("ObfuscateByte error\n")
			t.Fail()
		}

		outIn, err := DeobfuscateByte(obfOut, 0x55, 0x55)
		if err != nil {
			t.Logf("DeObfuscateByte error\n")
			t.Fail()
		}

		if obfIn[0] != outIn[0] {
			t.Logf("matching error %02x vs %02x\n", obfIn[0], outIn[0])
			t.Fail()
		}
	}
}

func TestObfuscateError(t *testing.T) {
	obfOut, err := ObfuscateByte(nil, 0x55, 0x55)
	if err == nil || obfOut != nil {
		t.Logf("ObfuscateByte Error Test\n")
		t.Fail()
	}

	obfOut, err = Obfuscate(nil)
	if err == nil || obfOut != nil {
		t.Logf("Obfuscate Error Test\n")
		t.Fail()
	}
}

func TestDeObfuscateError(t *testing.T) {
	obfOut, err := DeobfuscateByte(nil, 0x55, 0x55)
	if err == nil || obfOut != nil {
		t.Logf("DeobfuscateByte Error Test\n")
		t.Fail()
	}

	obfOut, err = DeobfuscateByte([]byte("123"), 0x55, 0x55)
	if err == nil || obfOut != nil {
		t.Logf("DeobfuscateByte Error Test\n")
		t.Fail()
	}

	obfOut, err = DeObfuscate(nil)
	if err == nil || obfOut != nil {
		t.Logf("Deobfuscate Error Test\n")
		t.Fail()
	}
}
