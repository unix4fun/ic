package ickp

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"github.com/unix4fun/ic/icutl"
	"io"
	"os"
	//"io/ioutil"
	//"strings"
	//"bytes"
)

const (
	KEYRSA = iota
	KEYECDSA
	KEYEC25519
)

type IdentityKey struct {
	keyType  int
	keyOwner string
	rsa      *rsa.PrivateKey
	ecdsa    *ecdsa.PrivateKey
	ec25519  *Ed25519PrivateKey
}

type IdentityPublicKey struct {
	KeyType  int
	KeyOwner string
	KeyBin   []byte
}

func (i *IdentityKey) Type() string {
	switch i.keyType {
	case KEYRSA:
		return "ac-rsa"
	case KEYECDSA:
		return "ac-ecdsa"
	case KEYEC25519:
		return "ac-ec25519"
	}
	return ""
}

func (i *IdentityKey) PubToFile(filename string) error {
	/*
		b := new(bytes.Buffer)

		pubStr, err := i.PubToPKIX()
		if err != nil {
		}

		//ioutil.WriteFile()
	*/
	return nil
}

func (i *IdentityKey) PubToPKIX() ([]byte, error) {
	/*
		var err error
		var keyBin, keyHdr []byte

		switch i.keyType {
		case KEYRSA:
			keyBin, err = x509.MarshalPKIXPublicKey(i.rsa.Public())
			keyHdr = []byte("ac-rsa")
		case KEYECDSA:
			keyBin, err = x509.MarshalPKIXPublicKey(i.ecdsa.Public())
			keyHdr = []byte("ac-ecdsa")
		case KEYEC25519:
			keyBin, err = asn1.Marshal(i.ec25519.Pub[:])
			keyHdr = []byte("ac-25519")
		default:
			return nil, errors.New("invalid key type")
		}

		if err != nil {
			return nil, err
		}
		b64comp, err := icutl.CompressData(keyBin)
		if err != nil {
			return nil, err
		}
		b64pub := icutl.B64EncodeData(b64comp)

	*/
	// let's write our stuff...
	/*
		wr.Write(keyHdr)
		wr.Write([]byte(" "))
		wr.Write(b64pub)
		wr.Write([]byte(" "))
		wr.Write([]byte(i.keyOwner))
	*/
	// we're good
	//return b64pub, nil
	return nil, nil
}

func PKIXToPub(rd io.Reader) (pub interface{}, err error) {
	/*
		pbuf, err := ioutil.ReadAll(rd)
		if err != nil {
			return nil, err
		}

		pstrArr := strings.Split(string(pbuf), " ")
		if len(pstrArr) != 3 {
			return nil, errors.New("invalid pubkey file")
		}

		deb64, err := icutl.B64DecodeData(pstrArr[1])
		if err != nil {
			return nil, err
		}

		pubraw, err := icutl.DecompressData(deb64)
		if err != nil {
			return nil, err
		}
	*/

	return nil, nil
}

func (i *IdentityKey) PrivToPKIX(wr io.Writer, passwd []byte) error {
	var keyHeader string
	var keyDer []byte
	var err error

	switch i.keyType {
	case KEYRSA:
		keyHeader = "RSA PRIVATE KEY"
		keyDer = x509.MarshalPKCS1PrivateKey(i.rsa)
	case KEYECDSA:
		keyHeader = "ECDSA PRIVATE KEY"
		keyDer, err = x509.MarshalECPrivateKey(i.ecdsa)
	case KEYEC25519:
		keyHeader = "EC25519 PRIVATE KEY"
		keyDer, err = asn1.Marshal(i.ec25519.Pub[:])
	default:
		return errors.New("invalid key type")
	}
	if err != nil {
		return err
	}
	pemKey, err := AEADEncryptPEMBlock(rand.Reader, keyHeader, keyDer, passwd)
	if err != nil {
		return err
	}
	return pem.Encode(wr, pemKey)
}

func (i *IdentityKey) ToKeyFiles(prefix string, passwd []byte) error {
	/*
		pubFile, err := os.OpenFile(prefix+".pub", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		defer pubFile.Close()
		if err != nil {
			return err
		}
	*/
	privFile, err := os.OpenFile(prefix, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0700)
	defer privFile.Close()
	if err != nil {
		return err
	}

	//err = i.PubToPKIX(pubFile)
	err = i.PubToFile(prefix + ".pub")
	if err != nil {
		return err
	}

	err = i.PrivToPKIX(privFile, passwd)
	if err != nil {
		return err
	}

	return nil
}

// will try to load fprefix.pub / fprefix
func FromKeyFiles(prefix string) (i *IdentityKey, err error) {
	pubFile, err := os.Open(prefix + ".pub")
	defer pubFile.Close()
	if err != nil {
		return nil, err
	}
	privFile, err := os.Open(prefix)
	defer privFile.Close()
	if err != nil {
		return nil, err
	}
	return nil, nil
}

func NewIdentityKey(keytype int, owner string) (*IdentityKey, error) {
	var err error
	i := new(IdentityKey)

	icutl.DebugLog.Printf("bleh bleh keygen for %s\n", owner)

	switch keytype {
	case KEYRSA:
		i.keyType = keytype
		i.rsa, err = GenKeysRSA(rand.Reader)
	case KEYECDSA:
		i.keyType = keytype
		i.ecdsa, err = GenKeysECDSA(rand.Reader)
	/*
		//fmt.Printf("ECDSAAAAA: %v / %v\n", i.ecdsa, err)
		jsonProut, err := json.Marshal(i.ecdsa.Public())
		jsonTa, err := json.Marshal(i.ecdsa)
		fmt.Printf("ERROR: %s\n", err)
		b64comp, err := icutl.CompressData(jsonProut)
		b64pub := icutl.B64EncodeData(b64comp)
		fmt.Printf("JSON PublicKey: %s\n", jsonProut)
		fmt.Printf("JSON PublicKey: ac-ecdsa %s\n", b64pub)
		fmt.Printf("JSON AllKey: %s\n", jsonTa)

		pkixKey, err := x509.MarshalPKIXPublicKey(i.ecdsa.Public())
		if err != nil {
			panic(err)
		}
		b64comp, err = icutl.CompressData(pkixKey)
		b64pub = icutl.B64EncodeData(b64comp)
		fmt.Printf("PKIX PublicKey: ac-ecdsa %s\n", b64pub)
	*/

	case KEYEC25519:
		i.keyType = keytype
		i.ec25519, err = GenKeysED25519(rand.Reader)

	/*
		pkixKey, err := asn1.Marshal(i.ec25519.Pub[:])
		if err != nil {
			panic(err)
		}
		b64comp, err := icutl.CompressData(pkixKey)
		b64pub := icutl.B64EncodeData(b64comp)
		fmt.Printf("PKIX PublicKey: ac-ed25519 %s\n", b64pub)
	*/
	default:
		err = errors.New("invalid type")
		return nil, err
	}
	//fmt.Printf("C'EST BON ON A FINI\n")
	i.keyOwner = owner
	return i, nil
}
