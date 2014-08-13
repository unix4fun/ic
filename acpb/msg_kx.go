package acpb

import (
    "fmt"
    "os"
//    "bytes"
//    "log"
//    "net"
//    "time"
//    "crypto/rand"
    "encoding/hex"
    "github.com/unix4fun/ac/proto"
    "code.google.com/p/goprotobuf/proto"
)

func KXPACK_Handler(acMessageKxReq *AcKeyExchangeMessageRequest) (acMsgResponse *AcKeyExchangeMessageResponse, err error) {
    var responseType AcKeyExchangeMessageResponseAcKXRespMsgType
    responseType = AcKeyExchangeMessageResponse_KXR_PACK
    //var acctx * acproto.ACMsgContext

    //fmt.Printf("KXPACK Message: let's give the key\n")
    //fmt.Printf("from myNick: %s\n", acMessageKxReq.GetMynick())
    //fmt.Printf("to peerNick: %s\n", acMessageKxReq.GetPeernick())
    //fmt.Printf("channel: %s\n", acMessageKxReq.GetChannel())

    channel := acMessageKxReq.GetChannel()
    mynick := acMessageKxReq.GetMynick()
    peernick := acMessageKxReq.GetPeernick()
    reqServ := acMessageKxReq.GetServer()
    fmt.Fprintf(os.Stderr, "[+] KXPACK <- DH( %s/%s <KX> '%s' -> '%s' ) \n", channel, reqServ, mynick, peernick)

    if len(channel) == 0 || len(mynick) == 0 || len(peernick) == 0 || len(reqServ) == 0 {
        retErr := acpbError(-1, "KXPACK_Handler().args(channel|serv|mynick|peernick): 0 bytes", nil)
        acMsgResponse = &AcKeyExchangeMessageResponse {
            Type: &responseType,
            Bada: proto.Bool(false),
            ErrorCode: proto.Int32(-1),
        }
        fmt.Fprintf(os.Stderr, "[!] KXPACK -> (R) -1 ! %s\n", retErr.Error())
        return acMsgResponse, retErr
    }

    //func (psk PSKMap) GetSKMapEntry(server string, channel string) (*ACMsgContext, bool) {
    //acctx, ok_a := Sk[channel]
    acctx, ok_a := ACmap.GetSKMapEntry(reqServ, channel)
    //fmt.Print(ok_a)
    //me, ok_b := Pk[mynick]
    me, ok_b := ACmap.GetPKMapEntry(reqServ, mynick)
    //fmt.Print(ok_b)
    //peer, ok_c := Pk[peernick]
    peer, ok_c := ACmap.GetPKMapEntry(reqServ, peernick)
    //fmt.Print(ok_c)

    if ok_a == false || ok_b == false || ok_c == false {
        retErr := acpbError(-2, "KXPACK_Handler().GetSKMapEntry/GetPKMapEntry(): failed ", nil)
        acMsgResponse = &AcKeyExchangeMessageResponse {
            Type: &responseType,
            Bada: proto.Bool(false),
            ErrorCode: proto.Int32(-2),
        }
        fmt.Fprintf(os.Stderr, "[!] KXPACK -> (R) -2 ! %s\n", retErr.Error())
        return acMsgResponse, retErr
    }

    // XXX ok this is how we handle private and channel key exchange as in
    // private/queries there is no "channel"
    // we're going to see if it's a channel or private message key exchange
    // if it's channel we build a "channel"
    // KXPACK => mynick=peernick
    // KXUNPACK => peernick=mynick
    //
    // TODO: to move into CreateKXMessage and OpenKXMessage
//    kx_channel := []byte(channel)
//    ok_channel, _ :=  acproto.IsValidChannelName(kx_channel)
//    fmt.Printf("[+] KXPACK: is %s a valid channel: %t\n", channel, ok_channel)
//    if ok_channel == false {
//        //kx_channel := channel
//        // nonce building!
//        kxc_build := new(bytes.Buffer)
//        kxc_build.Write([]byte(mynick))
//        kxc_build.WriteByte(byte('='))
//        kxc_build.Write([]byte(peernick))
//        kx_channel = kxc_build.Bytes()
//        fmt.Printf("[+] KXPACK: not a channel, private conversation let's use this: %s\n", kx_channel)
//    }

    //fmt.Printf("KEY: %s\n", hex.EncodeToString(acctx.GetKey()))
    kxMsg, err := acproto.CreateKXMessage(acctx, peer.GetPubkey(), me.GetPrivkey(), []byte(channel), []byte(mynick), []byte(peernick))
    //fmt.Printf("kxMsg: %s\n", kxMsg)
    if err != nil {
        retErr := acpbError(-3, "KXPACK_Handler().CreateKXMessage(): ", err)
        acMsgResponse = &AcKeyExchangeMessageResponse {
            Type: &responseType,
            Bada: proto.Bool(false),
            ErrorCode: proto.Int32(-3),
        }
        return acMsgResponse, retErr
    }

    acMsgResponse = &AcKeyExchangeMessageResponse {
        Type: &responseType,
        Bada: proto.Bool(true),
        Blob: kxMsg,
        ErrorCode: proto.Int32(0),
        Nonce: proto.Uint32(acctx.GetNonce()),
    }
    fmt.Fprintf(os.Stderr, "[+] KXPACK -> (R) 0 ! Key [%s/%s] %s packed for %s\n", reqServ, channel, hex.EncodeToString(acctx.GetKey()), peernick)
    return acMsgResponse, nil
}

func KXUNPACK_Handler(acMessageKxReq *AcKeyExchangeMessageRequest) (acMsgResponse *AcKeyExchangeMessageResponse, err error) {
    var responseType AcKeyExchangeMessageResponseAcKXRespMsgType
    responseType = AcKeyExchangeMessageResponse_KXR_PACK
    //var acctx * acproto.ACMsgContext

    channel := acMessageKxReq.GetChannel()
    mynick := acMessageKxReq.GetMynick()
    peernick := acMessageKxReq.GetPeernick()
    blobMsg := acMessageKxReq.GetBlob()
    reqServ := acMessageKxReq.GetServer()

    fmt.Fprintf(os.Stderr, "[+] KXUNPACK <- DH( %s/%s <KX:%s> '%s' -> '%s' ) \n", channel, reqServ, blobMsg, peernick, mynick)
//    fmt.Printf("KX UNPACK BLOB: %s\n", blobMsg)

    // XXX TODO: missing the server..
    if len(channel) == 0 || len(mynick) == 0 || len(peernick) == 0 || len(blobMsg) == 0 || len(reqServ) == 0 {
        retErr := acpbError(-1, "KXUNPACK_Handler().args(channel|serv|mynick|peernick): 0 bytes", nil)
        acMsgResponse = &AcKeyExchangeMessageResponse {
            Type: &responseType,
            Bada: proto.Bool(false),
            ErrorCode: proto.Int32(-1),
        }
        fmt.Fprintf(os.Stderr, "[!] KXUNPACK -> (R) -1 ! %s\n", retErr.Error())
        return acMsgResponse, retErr
    }

    //acctx, ok_a := Sk[channel]
    //me, ok_b := Pk[MAPMYKEY]
//    fmt.Fprintf(os.Stderr, "FIRST ME\n")
    me, ok_b := ACmap.GetPKMapEntry(reqServ, mynick)
    //me, ok_b := Pk[mynick]
//    fmt.Fprintf(os.Stderr, "THEN PEER\n")
    peer, ok_c := ACmap.GetPKMapEntry(reqServ, peernick)
    //peer, ok_c := Pk[peernick]

//    fmt.Println(ok_b)
//    fmt.Println(ok_c)
    if ok_b == false || ok_c == false || peer.GetPubkey() == nil || me.GetPrivkey() == nil {
        retErr := acpbError(-2, "KXUNPACK_Handler().PKMapLookup(mynick|peernick) failure", nil)
        acMsgResponse = &AcKeyExchangeMessageResponse {
            Type: &responseType,
            Bada: proto.Bool(false),
            ErrorCode: proto.Int32(-2),
        }
        fmt.Fprintf(os.Stderr, "[!] KXUNPACK -> (R) -2 ! GetPKMapEntry(%s): %t - GetPKMapEntry(%s): %t\n%s\n", mynick, ok_b, peernick, ok_c, retErr.Error())
        return acMsgResponse, retErr
    }


    //acctx, err := CreateACContext(channel

    // XXX ok this is how we handle private and channel key exchange as in
    // private/queries there is no "channel"
    // we're going to see if it's a channel or private message key exchange
    // if it's channel we build a "channel"
    // KXPACK => mynick=peernick
    // KXUNPACK => peernick=mynick
//    kx_channel := []byte(channel)
//    ok_channel, _ :=  acproto.IsValidChannelName(kx_channel)
//    fmt.Printf("[+] KXUNPACK: is %s a valid channel: %t\n", channel, ok_channel)
//    if ok_channel == false {
//        // private channel building!
//        kxc_build := new(bytes.Buffer)
//        kxc_build.Write([]byte(peernick))
//        kxc_build.WriteByte(byte('='))
//        kxc_build.Write([]byte(mynick))
//        kx_channel = kxc_build.Bytes()
//        fmt.Printf("[+] KXUNPACK: not a channel, private conversation let's use this: %s\n", kx_channel)
//    }

    acctx, err := acproto.OpenKXMessage(peer.GetPubkey(), me.GetPrivkey(), blobMsg, []byte(channel), []byte(mynick), []byte(peernick))
//    acctx, err := acproto.OpenKXMessage(peer.GetPubkey(), me.GetPrivkey(), blobMsg, kx_channel, []byte(mynick), []byte(peernick))
    if err != nil {
        retErr := acpbError(-3, "KXUNPACK_Handler().OpenKXMessage(): ", err)
        acMsgResponse = &AcKeyExchangeMessageResponse {
            Type: &responseType,
            Bada: proto.Bool(false),
            ErrorCode: proto.Int32(-3),
        }
        fmt.Fprintf(os.Stderr, "[!] KXUNPACK -> (R) -3 ! %s\n", retErr.Error())
        return acMsgResponse, retErr
    }

    //fmt.Printf("reqServ: %s channel: %s key: %s\n", reqServ, channel, hex.EncodeToString(acctx.GetKey()))
    ACmap.SetSKMapEntry(reqServ, channel, acctx)
    acMsgResponse = &AcKeyExchangeMessageResponse {
        Type: &responseType,
        Bada: proto.Bool(true),
        ErrorCode: proto.Int32(0),
        Nonce: proto.Uint32(acctx.GetNonce()),
    }
    // XXX TODO REMOVE THE REAL DISPLAY OF THE KEY!!!!
    fmt.Fprintf(os.Stderr, "[+] KXUNPACK -> (R) 0 ! Key [%s/%s]: %s Unpacked\n", reqServ, channel, hex.EncodeToString(acctx.GetKey()) )
    return acMsgResponse, nil
}

//
//
// Handle Key Exchange MESSAGES..
//
//
func HandleACKxMsg(msg []byte) (msgReply []byte, err error) {
    var acReplyKxMsg *AcKeyExchangeMessageResponse
//    fmt.Fprintf(os.Stderr, "HandleACPkMsg()\n")

    // unpack the old message
    acMessageKxReq := &AcKeyExchangeMessageRequest {}
    proto.Unmarshal(msg, acMessageKxReq)

    switch kxMsg := acMessageKxReq.GetType(); kxMsg {
    case AcKeyExchangeMessageRequest_KX_PACK:
//        fmt.Fprintf(os.Stderr, "PACK KX Message:!\n")
        // TODO we don't handle errors correctly yet...
        acReplyKxMsg, err = KXPACK_Handler(acMessageKxReq)
    case AcKeyExchangeMessageRequest_KX_UNPACK:
//        fmt.Fprintf(os.Stderr, "UNPACK KX Message:!\n")
        // TODO we don't handle errors correctly yet...
        acReplyKxMsg, err = KXUNPACK_Handler(acMessageKxReq)
    default:
//        fmt.Fprintf(os.Stderr, "UNKNOWN Message: WTF?!?!\n")
        // TODO need to send a valid reponse with error -255
    }

    msgReply, err = proto.Marshal(acReplyKxMsg)
    return msgReply, err
}
