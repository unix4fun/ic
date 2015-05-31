// +build go1.4

package ackp

import (
	"bytes"
	//"encoding/gob"
	"fmt"
	"github.com/unix4fun/ac/acutl"
	"os"
	"encoding/json"
	//"io"
	"io/ioutil"
	"crypto/rand"
	"encoding/pem"
	"os/user"
)

// some variable to handle the maps and the run loop
var ACmap *PSKMap
var ACrun bool
var AcSaveFile string
var LocalUser *user.User
var AcHomeDir string

// import the package?! here is the init part
func init() {
	if ACmap == nil {
		ACmap = NewPSKMap()
	}

	// init user directory..
	LocalUser, err := user.Current()
	AcHomeDir = fmt.Sprintf("%s/.ac", LocalUser.HomeDir)
	AcSaveFile = fmt.Sprintf("%s/maps", AcHomeDir)

	/* create our dir or nothing if it does exist already.. :) */
	os.MkdirAll(AcHomeDir, 0700)

	//acutl.DebugLog.Printf("Home: %p err: %s savefile: %p\n", LocalUser, err, AcSaveFile)
	fmt.Fprintf(os.Stderr, "Home: %p (%s) Err: %s Savefile: %p (%s)", LocalUser, LocalUser.HomeDir, err, AcSaveFile, AcSaveFile)
}

//
//
// we hash our data based on server we're connected to
// each entry will host channel keys and public keys within that server context
//
//
type AcCOMM struct {
	Pk *PKMap
	Sk *SKMap
	Rd *RDMap
}

func (ac *AcCOMM) Init() {
	ac.Pk = new(PKMap)
	(*ac.Pk) = make(PKMap)

	ac.Sk = new(SKMap)
	(*ac.Sk) = make(SKMap)

	ac.Rd = new(RDMap)
	(*ac.Rd) = make(RDMap)
}

/* AcCOMM display function.. */
func (ac *AcCOMM) String() string {
	buf := new(bytes.Buffer)

	_, _ = buf.WriteString(fmt.Sprintf("---\n"))
	// Public Keys
	buf.WriteString(fmt.Sprintf("- PK\n"))
	for k, v := range *ac.Pk {
		_, _ = buf.WriteString(fmt.Sprintf("{%s}\n%v\n", k, v))
	}

	// Secret/Symmetric Keys
	buf.WriteString(fmt.Sprintf("- SK\n"))
	for k, v := range *ac.Sk {
		_, _ = buf.WriteString(fmt.Sprintf("{%s}\n%v\n", k, v))
	}

	// Random values
	buf.WriteString(fmt.Sprintf("- RD\n"))
	for k, v := range *ac.Rd {
		_, _ = buf.WriteString(fmt.Sprintf("{%s}\n%v\n", k, v))
	}

	_, _ = buf.WriteString(fmt.Sprintf("---\n"))
	return buf.String()
}

// this type is a map[string](*AcCOMM)
// it's a map defining a set of Public/Session Keys used for encrypting and KEX
// on a specific network based on the server name as hash key.
// its not perfect but it avoid basic one-client-multiple-network-same-nick-same-channels scenarios.
// is it too complicated? hmm we need to make it clear
type PSKMap map[string](*AcCOMM)

func NewPSKMap() (p *PSKMap) {
	p = new(PSKMap)
	(*p) = make(PSKMap)
	return
}

func (psk *PSKMap) String() string {
	buf := new(bytes.Buffer)
	for k, v := range *psk {
		// for each AcCOMM structure call String() of AcCOMM
		_, _ = buf.WriteString(fmt.Sprintf("-[%s]-\n%v\n", k, v))
	}
	return buf.String()
}

func (psk *PSKMap) Map2File(outfilestr string, keystr []byte) (bool, error) {
	/*
	 *
	 * here is the plan:
	 * 1. derive the key using salt and keystr.
	 * 2. prepare file format [ salt || encrypted_blob ].
	 * 3. marshal the PSKMap.
	 * 4. auth-encrypt the mashalled data.
	 * 5. write to file.
	 * 6. RSA sign the file.
	 *
	 */
	acutl.DebugLog.Printf("Map2FILE CALL to  %s\n", outfilestr)

	acutl.DebugLog.Printf("<< ACMAP DISPLAY:\n%v\n", ACmap)

	outfile, err := os.OpenFile(outfilestr, os.O_CREATE|os.O_WRONLY, 0700)
	defer outfile.Close()
	if err != nil {
		acutl.DebugLog.Printf("ERROR: %v", err)
		return false, err
	}

	jsonBuffer, err  := json.Marshal(ACmap)
	if err != nil {
		acutl.DebugLog.Printf("ERROR: %v", err)
		return false, err
	}

	jsonPem, err := AEADEncryptPEMBlock(rand.Reader, "ACMAP", jsonBuffer, keystr)
	if err != nil {
		acutl.DebugLog.Printf("ERROR: %v", err)
		return false, err
	}

	err = pem.Encode(outfile, jsonPem)
	if err != nil {
		acutl.DebugLog.Printf("ERROR: %v", err)
		return false, err
	}

	return true, nil
}

func (psk *PSKMap) File2Map(infilestr string, keystr []byte) (bool, error) {
	acutl.DebugLog.Printf("File2Map CALL to  %s\n", infilestr)

	fileBuffer, err := ioutil.ReadFile(infilestr)
	if err != nil {
		acutl.DebugLog.Printf("load file read error: %s", err)
		return false, err
	}

	aeadBuffer, _ := pem.Decode(fileBuffer)
	if aeadBuffer == nil {
		acutl.DebugLog.Printf("load file read error: %s", err)
		return false, err
	}

	jsonBuffer, err := AEADDecryptPEMBlock(aeadBuffer, keystr)
	if jsonBuffer == nil {
		acutl.DebugLog.Printf("load file read error: %s", err)
		return false, err
	}

	err = json.Unmarshal(jsonBuffer, ACmap)
	if err != nil {
		acutl.DebugLog.Printf("load file json unmarshalling error: %s", err)
		return false, err
	}

	return true, nil
}

//
// RDMaps
//
func (psk *PSKMap) GetRDMapEntry(server string, channel string) ([]byte, bool) {
	acutl.DebugLog.Printf("===---=-=-=--==- GetRDMapEntry[@%p] (serv: %s channel: %s)! --==-=---=-=-=-==-\n", psk, server, channel)
	rdmap, ok := psk.GetRDMap(server)
	if ok == true {
		val, ok := (*rdmap)[channel]
		return val, ok
	}
	return nil, false
}

func (psk *PSKMap) SetRDMapEntry(server, channel string, rnd []byte) {
	acutl.DebugLog.Printf("===---=-=-=--==- SetRDMapEntry[@%p] (serv: %s channel: %s)! --==-=---=-=-=-==-\n", psk, server, channel)
	/*
		if psk == nil {
			//(*psk) = make(PSKMap)
			acutl.DebugLog.Printf("===---=-=-=--==- Nil PSKMap! --==-=---=-=-=-==-\n")
			return &acutl.AcError{Value: -1, Msg: "Nil PSKMap", Err: nil}
		}
	*/
	rdmap, ok := psk.GetRDMap(server)
	if ok == true {
		delete((*rdmap), channel)
		(*rdmap)[channel] = rnd
		return
	}
	// the RDMap for this server is non existent, let's make it...
	psk.initRDMapWith(server, channel, rnd)
	return
}

func (psk *PSKMap) GetRDMap(server string) (*RDMap, bool) {
	acutl.DebugLog.Printf("===---=-=-=--==- GetRDMap[@%p] (serv: %s)! --==-=---=-=-=-==-\n", psk, server)
	acm, ok := (*psk)[server]
	if ok == true {
		return acm.Rd, true
	}
	return nil, false
}

// call only if RDMap s empty
func (psk *PSKMap) initRDMapWith(server string, channel string, rnd []byte) {
	ac := new(AcCOMM)
	ac.Init()
	(*psk)[server] = ac
	(*ac.Rd)[channel] = rnd
	return
}

//
// SKMaps
//
func (psk *PSKMap) GetSKMapEntry(server string, channel string) (*SecKey, bool) {
	acutl.DebugLog.Printf("===---=-=-=--==- GetSKMapEntry[@%p] (serv: %s channel: %s)! --==-=---=-=-=-==-\n", server, channel)
	skmap, ok := psk.GetSKMap(server)
	if ok == true {
		val, ok := (*skmap)[channel]
		//fmt.Fprintf(os.Stderr, "===---=-=-=--==- GetSKMapEntry (serv: %s channel: %s) ! val: %p ok: %t --==-=---=-=-=-==-\n", server, channel, val, ok)
		return val, ok
	}
	return nil, false
}

func (psk *PSKMap) SetSKMapEntry(server string, channel string, sk *SecKey) {
	acutl.DebugLog.Printf("===---=-=-=--==- SetSKMapEntry[@%p] (serv: %s channel: %s)! --==-=---=-=-=-==-\n", psk, server, channel)
	// XXX MAKE SURE ACMap is allocated before using anything.
	/*
		if psk == nil {
			//*psk = make(PSKMap)
			acutl.DebugLog.Printf("===---=-=-=--==- Nil PSKMap! --==-=---=-=-=-==-\n")
			return &acutl.AcError{Value: -1, Msg: "Nil PSKMap", Err: nil}
		}
	*/
	skmap, ok := psk.GetSKMap(server)
	if ok == true {
		delete((*skmap), channel) // NO OP in case of nil..
		(*skmap)[channel] = sk
		return
	}
	// the SKMap for this server is non existent, let's make it...
	psk.initSKMapWith(server, channel, sk)
	return
}

func (psk *PSKMap) GetSKMap(server string) (*SKMap, bool) {
	acutl.DebugLog.Printf("===---=-=-=--==- GetSKMap[@%p] (serv: %s)! --==-=---=-=-=-==-\n", psk, server)
	acm, ok := (*psk)[server]
	if ok == true {
		return acm.Sk, true
	}
	return nil, false
}

// call only if SKMap s empty
func (psk *PSKMap) initSKMapWith(server string, channel string, sk *SecKey) {
	ac := new(AcCOMM)
	ac.Init()
	(*psk)[server] = ac
	(*ac.Sk)[channel] = sk
	return
}

//
// PKMaps
//
func (psk *PSKMap) GetPKMapEntry(server string, nick string) (*KexKey, bool) {
	acutl.DebugLog.Printf("===---=-=-=--==- GetPKMapEntry[@%p] (serv: %s nick: %s)! --==-=---=-=-=-==-\n", psk, server, nick)
	pkmap, ok := psk.GetPKMap(server)
	if ok == true {
		val, ok := (*pkmap)[nick]
		//fmt.Fprintf(os.Stderr, "===---=-=-=--==- GetPKMapEntry (serv: %s nick: %s) ! val: %p ok: %t --==-=---=-=-=-==-\n", server, nick, val, ok)
		//        fmt.Println(val)
		//        fmt.Println(ok)
		return val, ok
	}
	return nil, false
}

// XXX not our job to do initial root data struct allocation... let's try..
func (psk *PSKMap) SetPKMapEntry(server string, nick string, pk *KexKey) {
	acutl.DebugLog.Printf("===---=-=-=--==- SetPKMapEntry[@%p] (serv: %s nick: %s)! --==-=---=-=-=-==-\n", psk, server, nick)
	/*
		if psk == nil {
			//(*psk) = make(PSKMap)
			//psk = NewPSKMap()
			fmt.Fprintf(os.Stderr, "===---=-=-=--==- Nil PSKMap! --==-=---=-=-=-==-\n" )
			return &acutl.AcError{Value: -1, Msg: "Nil PSKMap", Err: nil}
		}
	*/
	pkmap, ok := psk.GetPKMap(server)
	if ok == true {
		delete((*pkmap), nick) // NO OP in case of nil..
		(*pkmap)[nick] = pk
		return
	}

	// the PKMap for this server is non existent, let's make it...
	psk.initPKMapWith(server, nick, pk)
	return
}

func (psk *PSKMap) DelPKMapEntry(server, nick string) bool {
	acutl.DebugLog.Printf("===---=-=-=--==- DelPKMapEntry[@%p] (serv: %s nick: %s)! --==-=---=-=-=-==-\n", psk, server, nick)
	pkmap, ok := psk.GetPKMap(server)
	if ok == true {
		delete((*pkmap), nick)
		return true
	}
	return false
}

func (psk *PSKMap) GetPKMap(server string) (*PKMap, bool) {
	acutl.DebugLog.Printf("===---=-=-=--==- GetPKMap[@%p] (serv: %s)! --==-=---=-=-=-==-\n", psk, server)
	acm, ok := (*psk)[server]
	if ok == true {
		return acm.Pk, true
	}
	return nil, false
}

// call only if PKMap s empty
func (psk *PSKMap) initPKMapWith(server string, nick string, pk *KexKey) {
	ac := new(AcCOMM)
	ac.Init()
	(*psk)[server] = ac
	(*ac.Pk)[nick] = pk
	return
}

//
//
//
// This is for the public key cache
//
//
//
// XXX Pk map[string](*KexKey)
type PKMap map[string](*KexKey)

/*
func (pkm PKMap) Init() {
	pkm = make(PKMap)
}
*/

func (pkm *PKMap) String() string {
	buf := new(bytes.Buffer)

	for k, v := range *pkm {
		buf.WriteString(fmt.Sprintf("\\%s/\n%v\n", k, v))
	}

	return buf.String()
}

func (pkm *PKMap) GetPK(nick string) *KexKey {
	pk, ok := (*pkm)[nick]
	if ok == true {
		return pk
	}
	return nil
}

//
//
//
// This is for the CHANNEL/QUERY keys cache
//
//
//
//
type SKMap map[string](*SecKey)

/*
func (skm SKMap) Init() {
	skm = make(SKMap)
}
*/

func (skm *SKMap) String() string {
	buf := new(bytes.Buffer)

	for k, v := range *skm {
		buf.WriteString(fmt.Sprintf("\\%s/\n%v\n", k, v))
	}

	return buf.String()
}

func (skm *SKMap) GetSK(channel string) *SecKey {
	sk, ok := (*skm)[channel]
	if ok == true {
		return sk
	}
	return nil
}

// RDMap store the random value we use for "protecting/obfuscating" secret keys
// in memory, it is far from perfect, but better than pure plain text.
type RDMap map[string]([]byte)

func (rdm *RDMap) GetRD(channel string) []byte {
	rd, ok := (*rdm)[channel]
	if ok == true {
		return rd
	}
	return nil
}
