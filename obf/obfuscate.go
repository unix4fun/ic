package obf

import (
	"crypto/rand"
	"fmt"
)

const (
	MASK_HI = 1
	MASK_LO = 0
)

/*
I NEED TO DEFINE MASKs as a pair of byte constants..
const (
    MASK0 = []byte { 0x55, 0x55 }
    MASK1 = []byte { 0xf0, 0x0f }
    MASK2 = []byte { 0x0f, 0xf0 }
)
*/

type ObfuscateError struct {
	value int    // the error code.
	msg   string // the associated message
	err   error  // called layer error
}

func (oe ObfuscateError) Error() string {
	if oe.err != nil {
		oe.msg = fmt.Sprintf("ObfuscateError[%d]: %s:%s\n", oe.value, oe.msg, oe.err.Error())
	} else {
		oe.msg = fmt.Sprintf("ObfuscateError[%d]: %s\n", oe.value, oe.msg)
	}
	return oe.msg
}

func obfuscateError(val int, msg string, err error) (oe *ObfuscateError) {
	return &ObfuscateError{value: val, msg: msg, err: err}
}

func DeobfuscateByte(in []byte, mask_hi, mask_lo byte) (out []byte, err error) {
	if len(in) != 2 {
		// XXX need to return a real error there ...
		return nil, obfuscateError(-1, "DeobfuscateByte(): input len fail", nil)
	}
	cnt := 0
	//out = make([]byte, 1)
	//out [1]byte
	var tmp_out [1]byte
	out = tmp_out[:]

	for i := 7; i >= 0; i-- {
		if (mask_hi>>uint(i))&0x01 == 0x01 {
			out[0] |= (in[1] >> uint(i)) & 0x01
			if cnt != 7 {
				out[0] <<= 0x01
			}
			cnt++
		}
	}

	for i := 7; i >= 0; i-- {
		if (mask_lo>>uint(i))&0x01 == 0x01 {
			out[0] |= (in[0] >> uint(i)) & 0x01
			//if i != 0 { // NO NEED TO SHIFT ON THE LAST BIT
			if cnt != 7 { // THE EIGHT BIT MASK CAN BE DISTRIBUTED HOW YOU WANT INSIDE MASK_HI MASK_LO
				out[0] <<= 0x01
			}
			cnt++
		}
	}
	return
}

/* Arsene Obfuscation keep you busy where they is no need to :) */
// XXX need to plugin the fortuna PRNG instead...
func ObfuscateByte(in []byte, mask_hi, mask_lo byte) (out []byte, err error) {
	rnd := make([]byte, 2)
	out = make([]byte, 2)

	_, err = rand.Read(rnd)
	if err != nil {
		return nil, obfuscateError(-1, "ObfuscateByte() crypto/rand: ", err)
	}
	rnd[0] &= ^(mask_lo)
	rnd[1] &= ^(mask_hi)

	/* save the value */
	save := in[0]

	/* lo nibble */
	for i := 0; i < 8; i++ {
		if (mask_lo>>uint(i))&0x01 == 0x01 {
			out[0] |= (save & 0x01) << uint(i)
			save >>= 0x01
		} else {
			out[0] |= ((rnd[0] >> uint(i) & 0x01) << uint(i))
		}
	}

	/* hi nibble */
	for i := 0; i < 8; i++ {
		if (mask_hi>>uint(i))&0x01 == 0x01 {
			out[1] |= (save & 0x01) << uint(i)
			save >>= 0x01
		} else {
			out[1] |= ((rnd[1] >> uint(i) & 0x01) << uint(i))
		}
	}

	/*
	   fmt.Printf("MASKED RND[]: 0x%02x 0x%02x\n", rnd[1], rnd[0])
	   fmt.Printf("OBF IN[]: %02x\n", in[0])
	   fmt.Printf("OBF OUT[]: 0x%02x 0x%02x\n", out[1], out[0])
	*/
	return
}

/* can process it with any number of bytes */
func Obfuscate(in []byte) (out []byte, err error) {
	out = make([]byte, len(in)*2)
	//    var out []byte

	for i, _ := range in {
		/* mask have to be provided out */
		tmp, err := ObfuscateByte(in[i:i+1], 0x55, 0x55)
		if err != nil {
			return nil, obfuscateError(-1, "Obfuscate():", err)
		}
		out[i*2] = tmp[0]
		out[(i*2)+1] = tmp[1]
	}

	return
}

/* can process it with any number of bytes */
func DeObfuscate(in []byte) (out []byte, err error) {
	out = make([]byte, len(in)/2)
	//    fmt.Printf("len: %d\n", len(in))
	for i, _ := range out {
		//        fmt.Printf("i: %d\n", i)
		tmp, err := DeobfuscateByte(in[i*2:(i*2)+2], 0x55, 0x55)
		if err != nil {
			return nil, obfuscateError(-1, "DeObfuscate():", err)
		}
		out[i] = tmp[0]
	}

	return
}
