package acjs

import (
	"encoding/json"
	"fmt"
	"github.com/unix4fun/ac/acutl"
)

type ACPkMessage struct {
	Type   int    `json:"type"`
	Nick   string `json:"nick"`
	Host   string `json:"host"`
	Server string `json:"server"`
	Blob   []byte `json:"blob"`
}

type ACPkReply struct {
	Type  int    `json:"type"`
	Bada  bool   `json:"bada"`
	Errno int    `json:"errno"`
	Blob  []byte `json:"blob"`
}

func (pk *ACPkMessage) validate() error {
	acutl.DebugLog.Printf("CALL [%p] Validate(%d))\n", pk, pk.Type)

	if len(pk.Server) > 0 { // as Server information is needed by all requests
		switch pk.Type {
		case PKGEN:
			if len(pk.Nick) > 0 {
				acutl.DebugLog.Printf("RET [%p] Validate() -> PKGEN OK\n", pk)
				return nil
			}
		case PKADD:
			if len(pk.Nick) > 0 && len(pk.Blob) > 0 {
				acutl.DebugLog.Printf("RET [%p] Validate() -> PKADD OK\n", pk)
				return nil
			}
		case PKLIST:
			acutl.DebugLog.Printf("RET [%p] Validate() -> PKLIST OK\n", pk)
			return nil
		case PKDEL:
			if len(pk.Nick) > 0 {
				acutl.DebugLog.Printf("RET [%p] Validate() -> PKDEL OK\n", pk)
				return nil
			}
		} // end of switch
	} // end of if

	acutl.DebugLog.Printf("RET [%p] Validate(%d) -> [Error: Invalid PK message]\n", pk, pk.Type)
	return fmt.Errorf("Invalid PK[%d] message!\n", pk.Type)
}

func (pk *ACPkMessage) HandlerPKGEN() (msgReply []byte, err error) {
	acutl.DebugLog.Printf("CALL [%p] HandlePKGEN(%d:%s/%s)\n", pk, pk.Type, pk.Server, pk.Nick)

	err = pk.validate()
	if err != nil {
		msgReply, _ = json.Marshal(&ACPkReply{
			Type:  R_PKGEN,
			Bada:  false,
			Errno: -1,
			Blob:  []byte(err.Error()),
		})
		acutl.DebugLog.Printf("RET [%p] HandlePKGEN(%d:%s/%s) -> [Error: %s]\n", pk, pk.Type, pk.Server, pk.Nick, err.Error())
		return
	}

	myNewKeys, err := ackp.CreateKxKeys(pk.Nick, pk.Host, pk.Server)
	if err != nil {
		msgReply, _ = json.Marshal(&ACPkReply{
			Type:  R_PKGEN,
			Bada:  false,
			Errno: -2,
			Blob:  []byte(err.Error()),
		})
		acutl.DebugLog.Printf("RET [%p] HandlePKGEN(%d:%s/%s) -> [Error: %s]\n", pk, pk.Type, pk.Server, pk.Nick, err.Error())
		return
	}
	// create the cached version instead of in CreateMyKeys()
	PK, err := accp.CreatePKMessageNACL(myNewKeys.GetPubkey()[:])
	if err != nil {
		msgReply, _ = json.Marshal(&ACPkReply{
			Type:  R_PKGEN,
			Bada:  false,
			Errno: -3,
			Blob:  []byte(err.Error()),
		})
		acutl.DebugLog.Printf("RET [%p] HandlePKGEN(%d:%s/%s) -> [Error: %s]\n", pk, pk.Type, pk.Server, pk.Nick, err.Error())
		return
	}
	myNewKeys.Pubkey = string(PK)

	// create the Public Key storage if it's empty...
	ackp.ACmap.SetPKMapEntry(pk.Server, pk.Nick, myNewKeys)

	// all good we return the data
	msgReply, _ = json.Marshal(&ACPkReply{
		Type:  R_PKGEN,
		Bada:  true,
		Errno: 0,
	})
	acutl.DebugLog.Printf("RET [%p] HandlePKGEN(%d:%s/%s) -> [reply: %s]\n", pk, pk.Type, pk.Server, pk.Nick, msgReply)
	return
}

//
// HandlerPKADD is the final handler for PKADD control messages
func (pk *ACPkMessage) HandlerPKADD() (msgReply []byte, err error) {
	acutl.DebugLog.Printf("CALL [%p] HandlePKADD(%d:%s/%s)\n", pk, pk.Type, pk.Server, pk.Nick)

	err = pk.validate()
	if err != nil {
		msgReply, _ = json.Marshal(&ACPkReply{
			Type:  R_PKADD,
			Bada:  false,
			Errno: -1,
			Blob:  []byte(err.Error()),
		})
		acutl.DebugLog.Printf("RET [%p] HandlePKADD(%d:%s/%s) -> [Error: %s]\n", pk, pk.Type, pk.Server, pk.Nick, err.Error())
		return
	}

	//
	newkey := new(ackp.KexKey)
	newkey.Nickname = pk.Nick
	newkey.Userhost = pk.Host
	newkey.Server = pk.Server
	newkey.Pubkey = pk.Blob
	newkey.HasPriv = false
	newkey.CreaTime = time.Now()

	pubk, err := accp.OpenPKMessageNACL([]byte(pk.Blob))
	if err != nil {
		msgReply, _ = json.Marshal(&ACPkReply{
			Type:  R_PKADD,
			Bada:  false,
			Errno: -2,
			Blob:  []byte(err.Error()),
		})
		acutl.DebugLog.Printf("RET [%p] HandlePKADD(%d:%s/%s) -> [Error: %s]\n", pk, pk.Type, pk.Server, pk.Nick, err.Error())
		return
	}
	// XX check if it's a valid pubkey..
	err = newkey.SetPubkey(pubk)
	if err != nil {
		msgReply, _ = json.Marshal(&ACPkReply{
			Type:  R_PKADD,
			Bada:  false,
			Errno: -3,
			Blob:  []byte(err.Error()),
		})
		acutl.DebugLog.Printf("RET [%p] HandlePKADD(%d:%s/%s) -> [Error: %s]\n", pk, pk.Type, pk.Server, pk.Nick, err.Error())
		return
	}

	ackp.ACmap.SetPKMapEntry(pk.Server, pk.Nick, newkey)

	// all good we return the data
	msgReply, _ = json.Marshal(&ACPkReply{
		Type:  R_PKADD,
		Bada:  true,
		Errno: 0,
	})
	acutl.DebugLog.Printf("RET [%p] HandlePKADD(%d:%s/%s) -> [reply: %s]\n", pk, pk.Type, pk.Server, pk.Nick, msgReply)
	return
}

func (pk *ACPkMessage) HandlerPKLIST() (msgReply []byte, err error) {
	acutl.DebugLog.Printf("CALL [%p] HandlePKLIST(%d:%s/%s)\n", pk, pk.Type, pk.Server, pk.Nick)

	err = pk.validate()
	if err != nil {
		msgReply, _ = json.Marshal(&ACPkReply{
			Type:  R_PKLIST,
			Bada:  false,
			Errno: -1,
			Blob:  []byte(err.Error()),
		})
		acutl.DebugLog.Printf("RET [%p] HandlePKADD(%d:%s/%s) -> [Error: %s]\n", pk, pk.Type, pk.Server, pk.Nick, err.Error())
		return
	}

	pkMap, okMap := ackp.ACmap.GetPKMap(pk.Server)
	pkEntry, okEnt := ackp.ACmap.GetPKMapEntry(pk.Server, pk.Nick)

	// we have one entry for the request
	acutl.DebugLog.Printf("ok_map: %t ok_ent: %t\n", okMap, okEnt)
	switch {
	case okMap == true && len(pk.Nick) == 0: // REPLY ALL KEYS
		for _, myKeys := range *pkMap {
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

		msgReply, _ = json.Marshal(&ACPkReply{
			Type:  R_PKLIST,
			Bada:  true,
			Errno: 0,
		})
		/*
			acMsgResponse = &AcPublicKeyMessageResponse{
				Type:       &responseType,
				Bada:       proto.Bool(true),
				PublicKeys: acPubkeyArray,
				ErrorCode:  proto.Int32(0),
			}
		*/
		acutl.DebugLog.Printf("(RET) PKLIST -> (0) ! n Keys\n")
		return

	case okMap == true && okEnt == true: // REPLY ONE KEY
		// get the timestamp!!
		timestamp := pkEntry.CreaTime.Unix()
		// acPublicKey object
		//fmt.Fprintf(os.Stderr, "[+] PKLIST %s!%s @ %s / priv: %t\n", myKeys.Nickname, myKeys.Userhost, myKeys.Server, myKeys.HasPriv)
		acPubkey := &AcPublicKey{
			Nick:      &pkEntry.Nickname,
			Pubkey:    &pkEntry.Pubkey,
			Host:      &pkEntry.Userhost,
			Server:    &pkEntry.Server,
			Haspriv:   &pkEntry.HasPriv,
			Fp:        pkEntry.GetPubfp(),
			Timestamp: &timestamp,
		}
		// add that object to the array of public key..
		acPubkeyArray = append(acPubkeyArray, acPubkey)
		acMsgResponse = &AcPublicKeyMessageResponse{
			Type:       &responseType,
			Bada:       proto.Bool(true),
			PublicKeys: acPubkeyArray,
			ErrorCode:  proto.Int32(0),
		}
		acutl.DebugLog.Printf("(RET) PKLIST -> (0) ! one Key\n")
		return acMsgResponse, nil
	default: // NOTHING FOUND
		retErr := &acutl.AcError{Value: -2, Msg: "PKLIST_Handler(): nothing found!", Err: nil}
		msgReply, _ = json.Marshal(&ACPkReply{
			Type:  R_PKLIST,
			Bada:  false,
			Errno: -2,
			Blob:  []byte(err.Error()),
		})
		acutl.DebugLog.Printf("(RET[!]) PKLIST -> (-2) ! %s\n", retErr.Error())
		return acMsgResponse, retErr
	}

	// all good we return the data
	msgReply, _ = json.Marshal(&ACPkReply{
		Type:  R_PKLIST,
		Bada:  true,
		Errno: 0,
	})
	acutl.DebugLog.Printf("RET [%p] HandlePKLIST(%d:%s/%s) -> [reply: %s]\n", pk, pk.Type, pk.Server, pk.Nick)
	return
}

func (pk *ACPkMessage) HandlerPKDEL() (msgReply []byte, err error) {
	acutl.DebugLog.Printf("CALL [%p] HandlePKDEL(%d:%s/%s)\n", pk, pk.Type, pk.Server, pk.Nick)

	err = pk.validate()
	if err != nil {
		msgReply, _ = json.Marshal(&ACPkReply{
			Type:  R_PKDEL,
			Bada:  false,
			Errno: -1,
			Blob:  []byte(err.Error()),
		})
		acutl.DebugLog.Printf("RET [%p] HandlePKDEL(%d:%s/%s) -> [Error: %s]\n", pk, pk.Type, pk.Server, pk.Nick, err.Error())
		return
	}

	// all good we return the data
	msgReply, _ = json.Marshal(&ACPkReply{
		Type:  R_PKDEL,
		Bada:  true,
		Errno: 0,
	})
	acutl.DebugLog.Printf("RET [%p] HandlePKDEL(%d:%s/%s) -> [reply: %s]\n", pk, pk.Type, pk.Server, pk.Nick)
	return
}

//
//
// Handle PUBLIC KEY MESSAGES..
//
//
func HandlePKMsg(msg []byte) (msgReply []byte, err error) {
	acutl.DebugLog.Printf("CALL HandlePKMsg(msg[%d]:[%s])\n", len(msg), msg)
	req := &ACPkMessage{}

	// let's unmarshall the message first
	err = json.Unmarshal(msg, req)
	if err != nil {
		msgReply, _ = json.Marshal(&ACPkReply{
			Type:  R_PKERR,
			Bada:  false,
			Errno: -1,
			Blob:  []byte(err.Error()),
		})
		acutl.DebugLog.Printf("RET HandlerPKMsg(%s) -> [Error: %s]\n", msg, msgReply)
		return
	}

	switch req.Type {
	case PKGEN:
		msgReply, err = req.HandlerPKGEN()
	case PKADD:
		msgReply, err = req.HandlerPKADD()
	case PKLIST:
		msgReply, err = req.HandlerPKLIST()
	case PKDEL:
		msgReply, err = req.HandlerPKDEL()
	default:
		err = fmt.Errorf("Invalid PK Message.")
		msgReply, _ = json.Marshal(&ACPkReply{
			Type:  R_PKERR,
			Bada:  false,
			Errno: -2,
			Blob:  []byte(err.Error()),
		})
	}

	acutl.DebugLog.Printf("RET HandlePKMsg(msg[%d]:[%s]) -> [reply[%d]: %s]\n", len(msg), msg, len(msgReply), msgReply)
	return
}
