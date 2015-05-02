// +build go1.4
package acpb

// acpb == AC Protocol Buffer
import (
	"github.com/golang/protobuf/proto" // protobuf is now here.
	"github.com/unix4fun/ac/accp"
	"github.com/unix4fun/ac/ackp"
	"github.com/unix4fun/ac/acutl"
	"time"
)

func PKGEN_Handler(acMessagePkReq *AcPublicKeyMessageRequest) (acMsgResponse *AcPublicKeyMessageResponse, err error) {
	var responseType AcPublicKeyMessageResponseAcPKRespMsgType
	responseType = AcPublicKeyMessageResponse_PKR_GEN

	reqNick := acMessagePkReq.GetNick()
	reqHost := acMessagePkReq.GetHost()
	reqServ := acMessagePkReq.GetServer()

	acutl.DebugLog.Printf("(CALL) PKGEN <- %s ! %s / %s\n", reqNick, reqHost, reqServ)

	if len(reqServ) == 0 || len(reqNick) == 0 {
		retErr := &acutl.AcError{Value: -1, Msg: "PKGEN_Handler().Get{Nick|Server}(): 0 bytes", Err: nil}
		acMsgResponse = &AcPublicKeyMessageResponse{
			Type:      &responseType,
			Bada:      proto.Bool(false),
			ErrorCode: proto.Int32(-1),
			Blob:      []byte(retErr.Error()),
		}
		acutl.DebugLog.Printf("(RET[!]) PKGEN -> (-1) ! %s\n", retErr.Error())
		return acMsgResponse, retErr
	}

	myNewKeys, err := ackp.CreateKxKeys(reqNick, reqHost, reqServ)
	if err != nil {
		retErr := &acutl.AcError{Value: -2, Msg: "PKGEN_Handler().CreateMyKeys(): ", Err: err}
		acMsgResponse = &AcPublicKeyMessageResponse{
			Type:      &responseType,
			Bada:      proto.Bool(false),
			ErrorCode: proto.Int32(-2),
			Blob:      []byte(retErr.Error()),
		}
		acutl.DebugLog.Printf("(RET[!]) PKGEN -> (-2) ! %s\n", retErr.Error())
		return acMsgResponse, retErr
	}
	// create the cached version instead of in CreateMyKeys()
	PK, err := accp.CreatePKMessageNACL(myNewKeys.GetPubkey()[:])
	if err != nil {
		retErr := &acutl.AcError{Value: -3, Msg: "PKGEN_Handler().CreateCachePubkey: ", Err: err}
		acMsgResponse = &AcPublicKeyMessageResponse{
			Type:      &responseType,
			Bada:      proto.Bool(false),
			ErrorCode: proto.Int32(-3),
			Blob:      []byte(retErr.Error()),
		}
		acutl.DebugLog.Printf("(RET[!]) PKGEN -> (-3) ! %s\n", retErr.Error())
		return acMsgResponse, retErr
	}
	myNewKeys.Pubkey = string(PK)

	// create the Public Key storage if it's empty...
	ackp.ACmap.SetPKMapEntry(reqServ, reqNick, myNewKeys)
	acMsgResponse = &AcPublicKeyMessageResponse{
		Type:      &responseType,
		Bada:      proto.Bool(true),
		ErrorCode: proto.Int32(0),
	}
	acutl.DebugLog.Printf("(RET) PKGEN -> (0) ! Key Generated.\n")
	return acMsgResponse, nil
}

func PKADD_Handler(acMessagePkReq *AcPublicKeyMessageRequest) (acMsgResponse *AcPublicKeyMessageResponse, err error) {
	var responseType AcPublicKeyMessageResponseAcPKRespMsgType
	responseType = AcPublicKeyMessageResponse_PKR_ADD

	reqNick := acMessagePkReq.GetNick()
	reqHost := acMessagePkReq.GetHost()
	reqServ := acMessagePkReq.GetServer()
	reqPubkey := string(acMessagePkReq.GetBlob())

	acutl.DebugLog.Printf("(CALL) PKADD <- %s ! %s / %s (%s)\n", reqNick, reqHost, reqServ, reqPubkey)
	if len(reqServ) == 0 || len(reqNick) == 0 || len(reqPubkey) == 0 {
		retErr := &acutl.AcError{Value: -1, Msg: "PKADD_Handler().reqNick/Pubkey(): 0 bytes", Err: nil}
		acMsgResponse = &AcPublicKeyMessageResponse{
			Type:      &responseType,
			Bada:      proto.Bool(false),
			ErrorCode: proto.Int32(-1),
			Blob:      []byte(retErr.Error()),
		}
		acutl.DebugLog.Printf("(RET[!]) PKADD -> (-1) ! %s\n", retErr.Error())
		return acMsgResponse, retErr
	}

	newkey := new(ackp.KexKey)
	newkey.Nickname = reqNick
	newkey.Userhost = reqHost
	newkey.Server = reqServ
	newkey.Pubkey = reqPubkey
	newkey.HasPriv = false
	newkey.CreaTime = time.Now()

	pubk, err := accp.OpenPKMessageNACL([]byte(reqPubkey))
	if err != nil {
		retErr := &acutl.AcError{Value: -2, Msg: "PKADD_Handler().OpenPKMessage(): ", Err: err}
		acMsgResponse = &AcPublicKeyMessageResponse{
			Type:      &responseType,
			Bada:      proto.Bool(false),
			ErrorCode: proto.Int32(-2),
			Blob:      []byte(retErr.Error()),
		}
		acutl.DebugLog.Printf("(RET[!]) PKADD -> (-2) ! %s\n", retErr.Error())
		return acMsgResponse, retErr
	}
	// XX check if it's a valid pubkey..
	err = newkey.SetPubkey(pubk)
	if err != nil {
		retErr := &acutl.AcError{Value: -3, Msg: "PKADD_Handler().OpenPKMessage(weird keysize): ", Err: err}
		acMsgResponse = &AcPublicKeyMessageResponse{
			Type:      &responseType,
			Bada:      proto.Bool(false),
			ErrorCode: proto.Int32(-3),
			Blob:      []byte(retErr.Error()),
		}
		acutl.DebugLog.Printf("(RET[!]) PKADD -> (-3) ! %s\n", retErr.Error())
		return acMsgResponse, retErr
	}

	ackp.ACmap.SetPKMapEntry(reqServ, reqNick, newkey)
	// PK_ADD = 12; // request: type && nick && host && server && blob  -> add or update a public key
	acMsgResponse = &AcPublicKeyMessageResponse{
		Type:      &responseType,
		Bada:      proto.Bool(true),
		ErrorCode: proto.Int32(0),
	}
	acutl.DebugLog.Printf("(RET) PKADD -> (0) ! Key added.\n")
	return acMsgResponse, nil
}

// This is the PKLIST message handler.
// TODO: clear description of the logic.
func PKLIST_Handler(acMessagePkReq *AcPublicKeyMessageRequest) (acMsgResponse *AcPublicKeyMessageResponse, err error) {
	var responseType AcPublicKeyMessageResponseAcPKRespMsgType
	responseType = AcPublicKeyMessageResponse_PKR_LIST
	var acPubkeyArray []*AcPublicKey

	// request: type && my_nick                  -> list the public nick/fp/timestamp
	reqNick := acMessagePkReq.GetNick()
	reqServ := acMessagePkReq.GetServer()

	acutl.DebugLog.Printf("(CALL) PKLIST <- '%s' ! <host> / %s\n", reqNick, reqServ)
	if len(reqServ) == 0 {
		retErr := &acutl.AcError{Value: -1, Msg: "PKLIST_Handler().reqServ: 0 bytes", Err: nil}
		acMsgResponse = &AcPublicKeyMessageResponse{
			Type:      &responseType,
			Bada:      proto.Bool(false),
			ErrorCode: proto.Int32(-1), // on which network are you looking? are you connected?!
		}
		acutl.DebugLog.Printf("(RET[!]) PKLIST -> (-1) ! %s\n", retErr.Error())
		return acMsgResponse, retErr
	}

	Pk, _ := ackp.ACmap.GetPKMap(reqServ)

	if len(reqNick) > 0 { // IS A SPECIFIC NICK REQUESTED ?!?!
		myKeys, ok := Pk[reqNick]
		if ok == false { // We did NOT find the key! ERRORRRRRR!!
			retErr := &acutl.AcError{Value: -2, Msg: "PKLIST_Handler().reqNick(!)", Err: nil}
			acMsgResponse = &AcPublicKeyMessageResponse{
				Type:      &responseType,
				Bada:      proto.Bool(false),
				ErrorCode: proto.Int32(-2), // no such nickname
			}
			acutl.DebugLog.Printf("(RET[!]) PKLIST -> (-2) ! %s\n", retErr.Error())
			return acMsgResponse, retErr
		} else { // Key is in memory
			// get the timestamp!!
			timestamp := myKeys.CreaTime.Unix()
			// acPublicKey object
			//fmt.Fprintf(os.Stderr, "[+] PKLIST %s!%s @ %s / priv: %t\n", myKeys.Nickname, myKeys.Userhost, myKeys.Server, myKeys.HasPriv)
			acPubkey := &AcPublicKey{
				Nick:      &myKeys.Nickname,
				Pubkey:    &myKeys.Pubkey,
				Host:      &myKeys.Userhost,
				Server:    &myKeys.Server,
				Haspriv:   &myKeys.HasPriv,
				Fp:        myKeys.GetPubfp(),
				Timestamp: &timestamp,
			}
			// add that object to the array of public key..
			acPubkeyArray = append(acPubkeyArray, acPubkey)
			acMsgResponse = &AcPublicKeyMessageResponse{
				Type:       &responseType,
				Bada:       proto.Bool(true),
				PublicKeys: acPubkeyArray,
			}
			acutl.DebugLog.Printf("(RET) PKLIST -> (0) ! one Key\n")
			return acMsgResponse, nil
		}
	} else { // USER IS REQUESTING ALL KEYS STORED IN MEMORY
		for _, myKeys := range Pk {
			// get the timestamp!!
			timestamp := myKeys.CreaTime.Unix()
			// acPublicKey
			//fmt.Fprintf(os.Stderr, "[+] PKLIST %s!%s @ %s / priv: %t\n", myKeys.Nickname, myKeys.Userhost, myKeys.Server, myKeys.HasPriv)
			acPubkey := &AcPublicKey{
				Nick:      &myKeys.Nickname,
				Pubkey:    &myKeys.Pubkey,
				Host:      &myKeys.Userhost,
				Server:    &myKeys.Server,
				Haspriv:   &myKeys.HasPriv,
				Fp:        myKeys.GetPubfp(),
				Timestamp: &timestamp,
			}
			acPubkeyArray = append(acPubkeyArray, acPubkey)
		}

		acMsgResponse = &AcPublicKeyMessageResponse{
			Type:       &responseType,
			Bada:       proto.Bool(true),
			PublicKeys: acPubkeyArray,
		}
		acutl.DebugLog.Printf("(RET) PKLIST -> (0) ! n Keys\n")
		return acMsgResponse, nil
	} // end of else

	retErr := &acutl.AcError{Value: -3, Msg: "PKLIST_Handler().unHandled", Err: nil}
	acMsgResponse = &AcPublicKeyMessageResponse{
		Type:      &responseType,
		Bada:      proto.Bool(false),
		ErrorCode: proto.Int32(-3),
	}
	acutl.DebugLog.Printf("(RET[!]) PKLIST -> (-3) ! %s\n", retErr.Error())
	return acMsgResponse, retErr
}

// TODO: error code is not handled properly
func PKDEL_Handler(acMessagePkReq *AcPublicKeyMessageRequest) (acMsgResponse *AcPublicKeyMessageResponse, err error) {
	var responseType AcPublicKeyMessageResponseAcPKRespMsgType
	responseType = AcPublicKeyMessageResponse_PKR_DEL

	// request: type && nick && server                   -> delete the specific public key
	reqNick := acMessagePkReq.GetNick()
	reqServ := acMessagePkReq.GetServer()
	acutl.DebugLog.Printf("(CALL) PKDEL <- '%s' ! <host> / %s\n", reqNick, reqServ)

	if len(reqNick) > 0 && len(reqServ) > 0 { // IS A SPECIFIC NICK REQUESTED ?!?!
		//_, ok := Pk[reqNick]
		Pk, ok := ackp.ACmap.GetPKMap(reqServ)
		if ok == true {
			delete(Pk, reqNick)
			acMsgResponse = &AcPublicKeyMessageResponse{
				Type:      &responseType,
				Bada:      proto.Bool(true),
				ErrorCode: proto.Int32(0), // no such nickname
			}
			acutl.DebugLog.Printf("(RET) PKDEL -> (0) ! deleted key\n")
			return acMsgResponse, nil
		}
	}

	// XXX TODO: not sure If I should remove all keys or just return error
	retErr := &acutl.AcError{Value: -1, Msg: "PKDEL_Handler().reqServ|reqNick: 0 bytes", Err: nil}
	acMsgResponse = &AcPublicKeyMessageResponse{
		Type:      &responseType,
		Bada:      proto.Bool(false),
		ErrorCode: proto.Int32(-1), // no such nickname
	}
	acutl.DebugLog.Printf("(RET[!]) PKDEL -> (-1) ! missing argument\n")
	return acMsgResponse, retErr
}

//
//
// Handle PUBLIC KEY MESSAGES..
//
//
func HandleACPkMsg(msg []byte) (msgReply []byte, err error) {
	var acReplyPkMsg *AcPublicKeyMessageResponse
	//fmt.Printf("HandleACPkMsg()\n")

	// unpack the PK message
	acMessagePkReq := &AcPublicKeyMessageRequest{}
	err = proto.Unmarshal(msg, acMessagePkReq)
	// we cannot unpack the message...
	if err != nil {
		var responseType AcPublicKeyMessageResponseAcPKRespMsgType
		responseType = AcPublicKeyMessageResponse_PKR_ERR
		retErr := &acutl.AcError{Value: -1, Msg: "HandleACMsg().Unmarshall(PK): ", Err: err}
		acReplyPkMsg = &AcPublicKeyMessageResponse{
			Type:      &responseType,
			Bada:      proto.Bool(false),
			ErrorCode: proto.Int32(-1), // no such nickname
			Blob:      []byte(err.Error()),
		}
		err = retErr
	} else {
		switch pkMsg := acMessagePkReq.GetType(); pkMsg {
		case AcPublicKeyMessageRequest_PK_GEN:
			acReplyPkMsg, err = PKGEN_Handler(acMessagePkReq)
		case AcPublicKeyMessageRequest_PK_ADD:
			acReplyPkMsg, err = PKADD_Handler(acMessagePkReq)
		case AcPublicKeyMessageRequest_PK_LIST:
			acReplyPkMsg, err = PKLIST_Handler(acMessagePkReq)
		case AcPublicKeyMessageRequest_PK_DEL:
			acReplyPkMsg, err = PKDEL_Handler(acMessagePkReq)
		default:
			err = &acutl.AcError{Value: -255, Msg: "HandleACPkMsg(): unknown PK request!", Err: nil}
			acutl.DebugLog.Printf("(RET[!]) HandleACPkMsg(): unknown PK request\n")
			return nil, err
		} // END OF SWITCH
	} // ELSE

	msgReply, _ = proto.Marshal(acReplyPkMsg)
	return msgReply, err
}
