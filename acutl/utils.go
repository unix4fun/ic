package acutl

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/sha3" // sha3 is now here.
	"io"
	"io/ioutil"
	"log"
)

// protoError is the custom AC error type
// exporting the error code ad well as string and cascaded error message
type AcError struct {
	Value int    // the error code.
	Msg   string // the associated message
	Err   error  // called layer error
}

var DebugLog *log.Logger

func InitDebugLog(out io.Writer) {
	DebugLog = log.New(out, "<acDebug>:", log.Lmicroseconds|log.Lshortfile|log.LstdFlags)
}

func (ae *AcError) Error() string {
	if ae.Err != nil {
		ae.Msg = fmt.Sprintf("acError[%d]: %s:%s\n", ae.Value, ae.Msg, ae.Err.Error())
	} else {
		ae.Msg = fmt.Sprintf("acError[%d]: %s\n", ae.Value, ae.Msg)
	}
	return ae.Msg
}

func HashSHA3Data(input []byte) (out []byte, err error) {
	//sha3hash := sha3.NewKeccak256()
	sha3hash := sha3.New256()
	_, err = sha3hash.Write(input)
	if err != nil {
		//return nil, acprotoError(-1, "HashSHA3Data().Write(): ", err)
		//return nil, &protoError{value: -1, msg: "HashSHA3Data().Write(): ", err: err}
		return nil, &AcError{Value: -1, Msg: "HashSHA3Data().Write(): ", Err: err}
	}
	out = sha3hash.Sum(nil)
	return
}

func B64EncodeData(in []byte) (out []byte) {

	buffer := new(bytes.Buffer)
	encoder := base64.NewEncoder(base64.StdEncoding, buffer)
	encoder.Write(in)
	encoder.Close()

	out = buffer.Bytes()
	return out
}

func B64DecodeData(in []byte) (out []byte, err error) {
	b64str := make([]byte, base64.StdEncoding.DecodedLen(len(in)))

	b64strLen, err := base64.StdEncoding.Decode(b64str, in)
	if err != nil {
		return nil, &AcError{Value: -1, Msg: "B64DecodeData()||TooSmall: ", Err: err}
	}

	b64str = b64str[:b64strLen]
	return b64str, nil
}

//func CompressData(in []byte) (data *bytes.Buffer, err error) {
func CompressData(in []byte) (out []byte, err error) {

	// first let's compress
	data := new(bytes.Buffer)

	zbuf, err := zlib.NewWriterLevel(data, zlib.BestCompression)
	if err != nil {
		return nil, &AcError{Value: -1, Msg: "CompressData().zlib.NewWriterLevel(): ", Err: err}
	}

	n, err := zbuf.Write(in)
	if err != nil || n != len(in) {
		return nil, &AcError{Value: -2, Msg: "CompressData().zlib.Write(): ", Err: err}
	}

	//XXX funny  Flush don't actually flush stuff from zlib into the writer all the time.....
	//zbuf.Flush()
	// XXX let's try...
	zbuf.Close()

	//fmt.Fprintf(os.Stderr, "CompressData(%d B): %d B\n", len(in), data.Len())
	out = data.Bytes()
	return out, nil
}

func DecompressData(in []byte) (out []byte, err error) {
	zbuf := bytes.NewBuffer(in)
	plain, err := zlib.NewReader(zbuf)
	defer plain.Close()
	if err != nil {
		return nil, &AcError{Value: -1, Msg: "DecompressData().zlib.NewReader(): ", Err: err}
	}

	out, err = ioutil.ReadAll(plain)
	if err != nil && err != io.EOF {
		return nil, &AcError{Value: -2, Msg: "DecompressData().ioutil().ReadAll(): ", Err: err}
	}

	return out, nil
}

// XXX should len be uint32 or uint64 instead?
func GetRandomBytes(size int) (out []byte, err error) {
	newRnd := make([]byte, size)
	_, err = rand.Read(newRnd)
	if err != nil {
		return nil, err
	}
	return newRnd, nil
}
