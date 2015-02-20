// +build go1.4
package acpb

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"github.com/unix4fun/ac/accp"
	"os"
)

// some variable to handle the maps and the run loop
var ACmap PSKMap
var ACrun bool

// this type is a map[string](*AcCOMM)
// it's a map defining a set of Public/Session Keys used for encrypting and KEX
// on a specific network based on the server name as hash key.
// its not perfect but it avoid basic one-client-multiple-network-same-nick-same-channels scenarios.
// is it too complicated? hmm we need to make it clear
type PSKMap map[string](*AcCOMM)

func (psk PSKMap) Map2File(outfilestr string, salt []byte, keystr []byte) (bool, error) {

	/*
	 *
	 * here is the plan:
	 * 1. derive the key using salt and keystr.
	 * 2. prepare file format [ salt || encrypted_blob ].
	 * 3. marshal the PSKMap.
	 * 4. auth-encrypt the mashalled data.
	 * 5. write to file.
	 * 6. RSA sign the file.
	 */
	fmt.Fprintf(os.Stderr, "Map2FILE CALL to  %s", outfilestr)

	outfile, err := os.OpenFile(outfilestr, os.O_CREATE|os.O_WRONLY, 0700)
	//defer outfile.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v", err)
		return false, err
	}

	buff := new(bytes.Buffer)
	enc := gob.NewEncoder(buff)

	err = enc.Encode(ACmap)
	if err != nil {
		return false, err
	}

	fmt.Fprintf(os.Stderr, "marshalled : %d bytes\n", len(buff.Bytes()))
	n, err := outfile.Write(buff.Bytes())
	fmt.Fprintf(os.Stderr, "marshalled : %d bytes\n", len(buff.Bytes()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v", err)
		return false, err
	}
	fmt.Fprintf(os.Stderr, "writtent: %d bytes\n", n)
	return true, nil
}

func (psk PSKMap) File2Map(infilestr string, salt []byte, key []byte) {
	//fmt.Fprintf(os.Stderr, "File2Map CALL to  %s", outfilestr)
}

//
// RDMaps
//
func (psk PSKMap) GetRDMapEntry(server string, channel string) ([]byte, bool) {
	rdmap, ok := psk.GetRDMap(server)
	if ok == true {
		val, ok := rdmap[channel]
		return val, ok
	}
	return nil, false
}

func (psk PSKMap) SetRDMapEntry(server, channel string, rnd []byte) {
	rdmap, ok := psk.GetRDMap(server)
	if ok == true {
		delete(rdmap, channel)
		rdmap[channel] = rnd
		return
	}
	// the RDMap for this server is non existent, let's make it...
	psk.initRDMapWith(server, channel, rnd)
	return
}

func (psk PSKMap) GetRDMap(server string) (RDMap, bool) {
	acm, ok := psk[server]
	if ok == true {
		return acm.Rd, true
	}
	return nil, false
}

// call only if RDMap s empty
func (psk PSKMap) initRDMapWith(server string, channel string, rnd []byte) {
	ac := new(AcCOMM)
	ac.Init()
	psk[server] = ac
	ac.Rd[channel] = rnd
	return
}

//
// SKMaps
//
func (psk PSKMap) GetSKMapEntry(server string, channel string) (*accp.SecKey, bool) {
	skmap, ok := psk.GetSKMap(server)
	fmt.Fprintf(os.Stderr, "===---=-=-=--==- GetSKMapEntry (serv: %s channel: %s) ! skmap: %p ok: %t --==-=---=-=-=-==-\n", server, channel, skmap, ok)
	if ok == true {
		val, ok := skmap[channel]
		fmt.Fprintf(os.Stderr, "===---=-=-=--==- GetSKMapEntry (serv: %s channel: %s) ! val: %p ok: %t --==-=---=-=-=-==-\n", server, channel, val, ok)
		return val, ok
	}
	return nil, false
}

func (psk PSKMap) SetSKMapEntry(server string, channel string, sk *accp.SecKey) {
	skmap, ok := psk.GetSKMap(server)
	if ok == true {
		delete(skmap, channel) // NO OP in case of nil..
		skmap[channel] = sk
		return
	}
	// the SKMap for this server is non existent, let's make it...
	psk.initSKMapWith(server, channel, sk)
	return
}

func (psk PSKMap) GetSKMap(server string) (SKMap, bool) {
	acm, ok := psk[server]
	if ok == true {
		return acm.Sk, true
	}
	return nil, false
}

// call only if SKMap s empty
func (psk PSKMap) initSKMapWith(server string, channel string, sk *accp.SecKey) {
	ac := new(AcCOMM)
	ac.Init()
	psk[server] = ac
	ac.Sk[channel] = sk
	return
}

//
// PKMaps
//
func (psk PSKMap) GetPKMapEntry(server string, nick string) (*accp.KexKey, bool) {
	pkmap, ok := psk.GetPKMap(server)
	fmt.Fprintf(os.Stderr, "===---=-=-=--==- GetPKMapEntry (serv: %s nick: %s) ! pkmap: %p ok: %t --==-=---=-=-=-==-\n", server, nick, pkmap, ok)
	if ok == true {
		val, ok := pkmap[nick]
		fmt.Fprintf(os.Stderr, "===---=-=-=--==- GetPKMapEntry (serv: %s nick: %s) ! val: %p ok: %t --==-=---=-=-=-==-\n", server, nick, val, ok)
		//        fmt.Println(val)
		//        fmt.Println(ok)
		return val, ok
	}
	return nil, false
}

func (psk PSKMap) SetPKMapEntry(server string, nick string, pk *accp.KexKey) {
	pkmap, ok := psk.GetPKMap(server)
	if ok == true {
		delete(pkmap, nick) // NO OP in case of nil..
		pkmap[nick] = pk
		return
	}
	// the PKMap for this server is non existent, let's make it...
	psk.initPKMapWith(server, nick, pk)
	return
}

func (psk PSKMap) GetPKMap(server string) (PKMap, bool) {
	acm, ok := psk[server]
	if ok == true {
		return acm.Pk, true
	}
	return nil, false
}

// call only if PKMap s empty
func (psk PSKMap) initPKMapWith(server string, nick string, pk *accp.KexKey) {
	ac := new(AcCOMM)
	ac.Init()
	psk[server] = ac
	ac.Pk[nick] = pk
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
type PKMap map[string](*accp.KexKey)

func (pkm PKMap) Init() {
	pkm = make(PKMap)
}

func (pkm PKMap) GetPK(nick string) *accp.KexKey {
	pk, ok := pkm[nick]
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
type SKMap map[string](*accp.SecKey)

func (skm SKMap) Init() {
	skm = make(SKMap)
}

func (skm SKMap) GetSK(channel string) *accp.SecKey {
	sk, ok := skm[channel]
	if ok == true {
		return sk
	}
	return nil
}

// RDMap store the random value we use for "protecting/obfuscating" secret keys
// in memory, it is far from perfect, but better than pure plain text.
type RDMap map[string]([]byte)

func (rdm RDMap) GetRD(channel string) []byte {
	rd, ok := rdm[channel]
	if ok == true {
		return rd
	}
	return nil
}

//
//
// we hash our data based on server we're connected to
// each entry will host channel keys and public keys within that server context
//
//
type AcCOMM struct {
	Pk PKMap
	Sk SKMap
	Rd RDMap
}

func (ac *AcCOMM) Init() {
	ac.Pk = make(PKMap)
	ac.Sk = make(SKMap)
	ac.Rd = make(RDMap)
}
