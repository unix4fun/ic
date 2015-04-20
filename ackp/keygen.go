package ackp

import (
	"bytes"
	"crypto/rand"
	"github.com/unix4fun/ac/acutl"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
	"hash"
	"io"
)

type SecretKeyGen struct {
	hash        func() hash.Hash
	channel     []byte
	nick        []byte
	server      []byte
	input       []byte
	input_pbkdf []byte
	//    prng []byte
	info_hkdf []byte
}

func (skgen *SecretKeyGen) Init(input []byte, channel []byte, nick []byte, serv []byte) (err error) {
	//skgen.hash = sha3.NewKeccak256
	// go.crypto changed it... mlgrmlbmlbm
	skgen.hash = sha3.New256

	if input != nil {
		skgen.input = make([]byte, len(input))
		copy(skgen.input, input)
	} else { // handle empty input with crypto/rand input
		skgen.input = make([]byte, 1024)
		_, err = io.ReadFull(rand.Reader, skgen.input)
		if err != nil {
			return err
		}
	}

	if channel != nil {
		skgen.channel = make([]byte, len(channel))
		copy(skgen.channel, channel)
	}

	if nick != nil {
		skgen.nick = make([]byte, len(nick))
		copy(skgen.nick, nick)
	}

	if serv != nil {
		skgen.server = make([]byte, len(serv))
		copy(skgen.server, serv)
	}

	prng := make([]byte, 256)
	_, err = io.ReadFull(rand.Reader, prng)
	if err != nil {
		return err
		//        fmt.Fprintf(os.Stderr, "POUET POUET Error")
		//        fmt.Println(err)
	}

	//    fmt.Fprintf(os.Stderr, "read %d random bytes\n", n)
	//dk := pbkdf2.Key([]byte("some password"), salt, 4096, 32, sha1.New)
	//func Key(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte
	// XXX TODO be sure of the PBKDF2 FUNCTION CALL ARGUMENTS...
	skgen.input_pbkdf = pbkdf2.Key(skgen.input, prng, 16384, 32, skgen.hash)
	//    fmt.Fprintf(os.Stderr, "PBKDF LEN: %d\n", len(skgen.input_pbkdf))

	// in Read() we will apply the HKDF function.. onto the PBKDF2 derived key.
	// XXX TODO: just to be sure implement HASH of each value instead of values
	// only.
	str_build := new(bytes.Buffer)
	str_build.Write(serv)
	str_build.WriteByte(byte(':'))
	str_build.Write(nick)
	str_build.WriteByte(byte(':'))
	str_build.Write(channel)

	skgen.info_hkdf, err = acutl.HashSHA3Data(str_build.Bytes())
	if err != nil {
		return err
	}

	return nil
}

// XXX TODO: return err if init() or Reset() has not been called
func (skgen *SecretKeyGen) Read(p []byte) (n int, err error) {
	prng := make([]byte, 256)
	n, err = io.ReadFull(rand.Reader, prng)
	if err != nil {
		//fmt.Fprintf(os.Stderr, "POUET POUET PROUT Error")
		//fmt.Println(err)
		return n, err
	}

	my_hkdf := hkdf.New(skgen.hash, skgen.input_pbkdf, prng, skgen.info_hkdf)
	n, err = io.ReadFull(my_hkdf, p)
	return n, err
}
