package ickp

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/nu7hatch/gouuid"
	"github.com/unix4fun/ic/icutl"
	//"io/ioutil"
	//"strings"
	//"bytes"
)

const (
	KEYRSA = iota
	KEYECDSA
	KEYEC25519

	KeyRSAStr     = "ic-rsa"
	KeyECDSAStr   = "ic-ecdsa"
	KeyEC25519Str = "ic-25519"

	PEMHDR_RSA   = "RSA PRIVATE KEY"
	PEMHDR_ECDSA = "ECDSA PRIVATE KEY"
	PEMHDR_25519 = "EC25519 PRIVATE KEY"
)

var (
	S2K = map[string]int{
		KeyRSAStr:     KEYRSA,
		KeyECDSAStr:   KEYECDSA,
		KeyEC25519Str: KEYEC25519,
	}

	K2S = map[int]string{
		KEYRSA:     KeyRSAStr,
		KEYECDSA:   KeyECDSAStr,
		KEYEC25519: KeyEC25519Str,
	}
)

type IdentityKey struct {
	keyType  int
	keyOwner *uuid.UUID
	rsa      *rsa.PrivateKey
	ecdsa    *ecdsa.PrivateKey
	ec25519  *Ed25519PrivateKey
}

type IdentityPublicKey struct {
	KeyType int
	//	KeyOwner string
	KeyBin []byte
}

func (i *IdentityKey) Type() string {
	str, ok := K2S[i.keyType]
	if ok {
		return str
	}
	return ""
}

func (i *IdentityKey) PubToPKIX(wr io.Writer) error {

	var err error
	var keyBin, keyHdr []byte

	switch i.keyType {
	case KEYRSA:
		keyBin, err = x509.MarshalPKIXPublicKey(i.rsa.Public())
	case KEYECDSA:
		keyBin, err = x509.MarshalPKIXPublicKey(i.ecdsa.Public())
	case KEYEC25519:
		keyBin, err = asn1.Marshal(i.ec25519.Pub[:])
	default:
		return errors.New("invalid key type")
	}

	if err != nil {
		return err
	}
	b64comp, err := icutl.CompressData(keyBin)
	if err != nil {
		return err
	}
	b64pub := icutl.B64EncodeData(b64comp)

	tmphdr, ok := K2S[i.keyType]
	if !ok {
		return errors.New("invalid key type")
	}
	keyHdr = []byte(tmphdr) //[]byte("ic-rsa")

	// let's write our stuff...
	// XXX error checking...
	wr.Write(keyHdr)
	wr.Write([]byte(" "))
	wr.Write(b64pub)
	wr.Write([]byte(" "))
	wr.Write([]byte(i.keyOwner.String()))

	// we're good
	return nil
}

func (i *IdentityKey) PKIXToPub(rd io.Reader) (err error) {
	pbuf, err := ioutil.ReadAll(rd)
	if err != nil {
		return err
	}

	pstrArr := strings.Split(string(pbuf), " ")
	if len(pstrArr) != 3 {
		return errors.New("invalid pubkey file")
	}

	if len(pstrArr[0]) > 0 && len(pstrArr[1]) > 0 && len(pstrArr[2]) > 0 {

		// sanity checks before using the splits...
		keyType, ok := S2K[pstrArr[0]]
		if !ok || keyType != i.keyType {
			return errors.New("keytype confusion or invalid")
		}

		// uuid parse
		if i.keyOwner.String() != pstrArr[2] {
			return errors.New("invalid owner")
		}

		// decode the stuff..
		deb64, err := icutl.B64DecodeData([]byte(pstrArr[1]))
		if err != nil {
			return err
		}

		// decompress
		pubraw, err := icutl.DecompressData(deb64)
		if err != nil {
			return err
		}

		switch keyType {
		case KEYRSA:
			if i.rsa != nil {
				tempKey, err := x509.ParsePKIXPublicKey(pubraw)
				if err != nil {
					return err
				}
				i.rsa.PublicKey = *(tempKey.(*rsa.PublicKey))
				return nil
			}
			break
		case KEYECDSA:
			if i.ecdsa != nil {
				tempKey, err := x509.ParsePKIXPublicKey(pubraw)
				if err != nil {
					return err
				}
				i.ecdsa.PublicKey = *(tempKey.(*ecdsa.PublicKey))
				return nil
			}
			break
		case KEYEC25519:
			// TODO
			//keyBin, err = asn1.Unmarshal(pubraw)
		}
	}

	return errors.New("invalid key")
}

func (i *IdentityKey) PrivToPKIX(wr io.Writer, passwd []byte) error {
	var keyHeader string
	var keyDer []byte
	var err error

	switch i.keyType {
	case KEYRSA:
		keyHeader = PEMHDR_RSA // "RSA PRIVATE KEY"
		keyDer = x509.MarshalPKCS1PrivateKey(i.rsa)
	case KEYECDSA:
		keyHeader = PEMHDR_ECDSA //"ECDSA PRIVATE KEY"
		keyDer, err = x509.MarshalECPrivateKey(i.ecdsa)
	case KEYEC25519:
		keyHeader = PEMHDR_25519 //"EC25519 PRIVATE KEY"
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

func (i *IdentityKey) PKIXToPriv(rd io.Reader, passwd []byte) error {
	pbuf, err := ioutil.ReadAll(rd)
	if err != nil {
		return err
	}

	pemBlock, _ := pem.Decode(pbuf)
	if pemBlock == nil {
		return fmt.Errorf("no PEM found")
	}

	plainBlock, err := AEADDecryptPEMBlock(pemBlock, passwd)
	switch pemBlock.Type {
	case PEMHDR_RSA:
		i.keyType = KEYRSA

		// set the keyowner
		i.keyOwner, err = uuid.NewV5(uuid.NamespaceX500, plainBlock)

		// parse the key
		i.rsa, err = x509.ParsePKCS1PrivateKey(plainBlock)
		if err != nil {
			return err
		}

	case PEMHDR_ECDSA:
		i.keyType = KEYECDSA
		i.ecdsa, err = x509.ParseECPrivateKey(plainBlock)
		if err != nil {
			return err
		}
	case PEMHDR_25519:
		// TODO
	default:
		return errors.New("Invalid key type")
	}

	return nil
}

func (i *IdentityKey) ToKeyFiles(prefix string, passwd []byte) error {
	privFile, err := os.OpenFile(prefix, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0700)
	if err != nil {
		return err
	}
	defer privFile.Close()

	pubFile, err := os.OpenFile(prefix+".pub", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0700)
	if err != nil {
		return err
	}
	defer pubFile.Close()

	err = i.PubToPKIX(pubFile)
	if err != nil {
		return err
	}

	err = i.PrivToPKIX(privFile, passwd)
	if err != nil {
		return err
	}

	return nil
}

// just validation that the key is valid and complete..
func (i *IdentityKey) Validate() (err error) {
	switch i.keyType {
	case KEYRSA:
		err = i.rsa.Validate()
		if err != nil {
			return
		}
		/*
				privKeyDer := x509.MarshalPKCS1PrivateKey(i.rsa)
				keyOwner, err = uuid.NewV5(uuid.NamespaceX500, privKeyDer)
				if err != nil {
					return
				}

			if i.keyOwner != keyOwner {
				err = errors.New("Invalid owner")
			}
		*/
	case KEYECDSA:
		// TODO
	case KEYEC25519:
		// TODO
	}
	return
}

// will try to load fprefix.pub / fprefix
func (i *IdentityKey) FromKeyFiles(prefix string, passwd []byte) (err error) {
	pubFile, err := os.Open(prefix + ".pub")
	if err != nil {
		return err
	}
	defer pubFile.Close()

	privFile, err := os.Open(prefix)
	if err != nil {
		return err
	}
	defer privFile.Close()

	err = i.PKIXToPriv(privFile, passwd)
	if err != nil {
		return err
	}

	err = i.PKIXToPub(pubFile)
	if err != nil {
		return err
	}

	err = i.Validate()
	return err
}

func LoadIdentityKey(prefix string, passwd []byte) (i *IdentityKey, err error) {
	i = new(IdentityKey)

	err = i.FromKeyFiles(prefix, passwd)
	if err != nil {
		return nil, err
	}

	return i, nil
}

func NewIdentityKey(keytype int) (*IdentityKey, error) {
	var err error
	i := new(IdentityKey)

	icutl.DebugLog.Printf("bleh bleh keygen for %d\n", keytype)

	switch keytype {
	case KEYRSA:
		i.keyType = keytype
		i.rsa, err = GenKeysRSA(rand.Reader)
		privKeyDer := x509.MarshalPKCS1PrivateKey(i.rsa)
		i.keyOwner, err = uuid.NewV5(uuid.NamespaceX500, privKeyDer)
		if err != nil {
			icutl.DebugLog.Printf("UUID error\n")
			return nil, err
		}
		err = i.rsa.Validate()
		if err != nil {
			return nil, err
		}

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
	// UUID.
	//i.keyOwner = owner
	return i, nil
}
