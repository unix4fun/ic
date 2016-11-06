// +build go1.5

package iccp

import (
	"encoding/base64"
	"github.com/golang/protobuf/proto" // protobuf is now here.
	"github.com/unix4fun/ic/ickp"
	"github.com/unix4fun/ic/icutl"
	"golang.org/x/crypto/nacl/secretbox"
)

func packMessageAC(hdr uint32, nonce uint32, blob *[]byte) (out []byte, err error) {

	acOut := &ACPackedMessage{}
	acOut.Header = hdr
	acOut.Nonce = nonce
	acOut.Ciphertext = *blob
	//acOut.Options = proto.Uint32(10034)

	//fmt.Printf("Nonce: %d(%08x)\n", nonce, nonce)

	acPackedMsg, err := proto.Marshal(acOut)
	if err != nil {
		return nil, err
	}
	// XXX test for errors message..
	//fmt.Printf("AC Message TEST #1 : %d (%v)\n", len(acPackedMsg), err)
	//fmt.Printf("PACKED: %s\n", hex.EncodeToString(acPackedMsg))

	out = icutl.B64EncodeData(acPackedMsg)
	return out, nil
}

func unpackMessageAC(in []byte) (mNonce uint32, myHdr, ciphertext []byte, err error) {

	acIn := &ACPackedMessage{}
	err = proto.Unmarshal(in, acIn)
	if err != nil {
		return 0, nil, nil, err
	}

	myHdr, err = CheckHeader([]byte(msgHdrAC), acIn.Header)
	if err != nil {
		return 0, nil, nil, err
	}

	//XXX TODO more meaningful updates from here...
	//fmt.Printf("Nonce: %d(%08x)\n", acIn.GetNonce(), acIn.GetNonce())
	return acIn.Nonce, myHdr, acIn.Ciphertext, nil
}

// A very pragmatic approach to protobuf encoding it's roughly true for most cases.
// XXX TODO: need to fix/clean that!
func PredictLenNACL(input []byte) (outlen int) {
	zipped, err := icutl.CompressData(input)
	if err != nil {
		return 0
	}
	sboxLen := len(zipped)        // zipped data
	sboxLen += secretbox.Overhead // NACL hash appended
	sboxLen += 3                  // 1 byte pb header value type + 2 bytes size  for the bytes part in PB message
	sboxLen += 6                  // 1 byte pb header + 1 byte size + 4 bytes data for AC header in PB message
	sboxLen += 7                  // 1 byte pb header value type + 2 byte size + 4 bytes nonce
	sboxLen += 2                  // 1 byte pb header value type + 1 byte size
	outlen = base64.StdEncoding.EncodedLen(sboxLen)
	//outlen += 14
	icutl.DebugLog.Printf("PredictLenNACL(%d): %d\n", len(input), outlen)
	return outlen
}

//
// AC Message OLD Format:
// BASE64( 'AC' || 'NONCE_VALUE' || SECRETBOX( KEY, NONCE_AUTH, ZLIB( MSG ) )
//
// AC Message NEW Format:
// BASE64( 'AC' || 'OPTIONS' || 'NONCE_VALUE' || SECRETBOX( KEY, NONCE_AUTH, ZLIB( MSG ) )
//
// Nonce AUTH OLD Format:
// SHA3( 'CHANNEL' || ':' || 'SRC_NICK' || ':' || 'NONCE_VALUE' || ':' || 'HDR_RAW' )
//
// Nonce AUTH NEW Format:
// SHA3( SHA3('CHANNEL') || ':' || SHA3('SRC_NICK') || ':' || SHA3('NONCE_VALUE') || ':' || 'HDR_RAW=AC||OPTIONS||NONCE_VALUE' )
//
// OPTIONS:
// 0x01 = NaCL secretbox
// 0x02 = AES-GCM
// 0x?0 = PROTO VERSION [ 0 - 15 ]
//
//

func CreateACMessageNACL(context *ickp.SecretKey, rnd, msg, myNick []byte) (out []byte, err error) {
	//var noncebyte [24]byte

	/* lets build our header */
	myHdr, intHdr, err := BuildHeader([]byte(msgHdrAC))
	if err != nil {
		return nil, &icutl.AcError{Value: -1, Msg: "CreateACMessageNACL().BuildHeader(): ", Err: err}
	}

	// first let's compress
	myBody, err := icutl.CompressData(msg)
	if err != nil {
		return nil, &icutl.AcError{Value: -2, Msg: "CreateACMessageNACL().CompressData(): ", Err: err}
	}

	//BuildNonceAC(inonce uint32, bob, mynick, myhdr []byte) (nonce []byte, noncebyte *[24]byte, err error)
	_, noncebyte, err := BuildNonceAC(context.GetNonce(), context.GetBob(), myNick, myHdr)

	// OPEN the key
	// XXX new to check rnd and context.key are the same size
	/*
		for j := 0; j < len(rnd); j++ {
			context.key[j] = context.key[j] ^ rnd[j]
		}
	*/
	context.RndKey(rnd)

	// encrypt
	myCipher := secretbox.Seal(nil, myBody, noncebyte, context.GetSealKey())

	// close the key
	context.RndKey(rnd)
	/*
		for j := 0; j < len(rnd); j++ {
			context.key[j] = context.key[j] ^ rnd[j]
		}
	*/

	// XXX error checking
	out, err = packMessageAC(intHdr, context.GetNonce(), &myCipher)

	//fmt.Fprintf(os.Stderr, "NACL PB == AC MSG OUT[%d]: %s\n", len(out), out)
	//context.nonce++
	context.IncNonce(0)

	return out, nil
}

func OpenACMessageNACL(context *ickp.SecretKey, rnd, cmsg, peerNick, myNick []byte) (out []byte, err error) {
	//fmt.Fprintf(os.Stderr, "OpenACMessageNACL()\n")
	b64, err := icutl.B64DecodeData(cmsg)
	if err != nil {
		return nil, &icutl.AcError{Value: -1, Msg: "OpenACMessageNACL(): ", Err: err}
	}

	cnonce, myHdr, ciphertext, err := unpackMessageAC(b64)
	if err != nil {
		return nil, &icutl.AcError{Value: -2, Msg: "OpenACMessageNACL(): ", Err: err}
	}

	// XXX this is to handle private message instead of channel communication
	// as the destination are assymetrical eau's dst is frl and frl's dst is eau
	//
	ac_bob := context.GetBob()
	ok_bob, _ := IsValidChannelName(ac_bob)
	//fmt.Fprintf(os.Stderr, "[+] OpenACMessage: is %s a valid channel: %t\n", ac_bob, ok_bob)
	if ok_bob == false && len(myNick) > 0 {
		ac_bob = myNick
	}

	/* let's build the nonce */
	//BuildNonceAC(inonce uint32, bob, mynick, myhdr []byte) (nonce []byte, noncebyte *[24]byte, err error)
	_, noncebyte, err := BuildNonceAC(cnonce, ac_bob, peerNick, myHdr)

	// OPEN the key
	context.RndKey(rnd)
	// XXX new to check rnd and context.key are the same size
	/*
		for j := 0; j < len(rnd); j++ {
			context.key[j] = context.key[j] ^ rnd[j]
		}
	*/

	packed, ok := secretbox.Open(nil, ciphertext, noncebyte, context.GetSealKey())

	// Close the key
	context.RndKey(rnd)
	/*
		for j := 0; j < len(rnd); j++ {
			context.key[j] = context.key[j] ^ rnd[j]
		}
	*/

	if ok == false {
		//return nil, acprotoError(1, "OpenACMessage().SecretOpen(): false ", nil)
		return nil, &icutl.AcError{Value: -3, Msg: "OpenACMessageNACL().SecretOpen(): ", Err: nil}
	}

	out, err = icutl.DecompressData(packed)
	if err != nil {
		return nil, &icutl.AcError{Value: -3, Msg: "OpenACMessageNACL().DecompressData(): ", Err: err}
	}

	//nonceval = acIn.GetNonce()
	// update the nonce value
	/*
		if cnonce > context.nonce {
			context.nonce = cnonce + 1
		} else {
			context.nonce++
		}
	*/
	context.IncNonce(cnonce)
	return out, nil
	//return nil, nil
}
