package acpb

import (
    "fmt"
    "os"
    "arsene/ac/proto"
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

//
// SKMaps
//
func (psk PSKMap) GetSKMapEntry(server string, channel string) (*acproto.ACMsgContext, bool) {
    skmap, ok := psk.GetSKMap(server)
    fmt.Fprintf(os.Stderr, "===---=-=-=--==- GetSKMapEntry (serv: %s channel: %s) ! skmap: %p ok: %t --==-=---=-=-=-==-\n", server, channel, skmap, ok)
    if ok == true {
        val, ok := skmap[channel]
        fmt.Fprintf(os.Stderr, "===---=-=-=--==- GetSKMapEntry (serv: %s channel: %s) ! val: %p ok: %t --==-=---=-=-=-==-\n", server, channel, val, ok)
        return val, ok
    }
    return nil, false
}

func (psk PSKMap) SetSKMapEntry(server string, channel string, sk *acproto.ACMsgContext) {
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
    if ok  == true {
        return acm.Sk, true
    }
    return nil, false
}

// call only if SKMap s empty
func (psk PSKMap) initSKMapWith(server string, channel string, sk *acproto.ACMsgContext) {
    ac := new(AcCOMM)
    ac.Init()
    psk[server] = ac
    ac.Sk[channel] = sk
    return
}

//
// PKMaps
//
func (psk PSKMap) GetPKMapEntry(server string, nick string) (*acproto.ACMyKeys, bool) {
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

func (psk PSKMap) SetPKMapEntry(server string, nick string, pk *acproto.ACMyKeys) {
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
    if ok  == true {
        return acm.Pk, true
    }
    return nil, false
}

// call only if PKMap s empty
func (psk PSKMap) initPKMapWith(server string, nick string, pk *acproto.ACMyKeys) {
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
// XXX Pk map[string](*ACMyKeys)
type PKMap map[string](*acproto.ACMyKeys)

func (pkm PKMap) Init() {
    pkm = make(PKMap)
}

func (pkm PKMap) GetPK(nick string) (*acproto.ACMyKeys) {
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
type SKMap map[string](*acproto.ACMsgContext)

func (skm SKMap) Init() {
    skm = make(SKMap)
}

func (skm SKMap) GetSK(channel string) (*acproto.ACMsgContext) {
    sk, ok := skm[channel]
    if ok == true {
        return sk
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
}

func (ac * AcCOMM) Init() {
    ac.Pk = make(PKMap)
    ac.Sk = make(SKMap)
}
