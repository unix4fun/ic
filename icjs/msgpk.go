package icjs

import (
	"encoding/json"
	"fmt"
	"github.com/unix4fun/ic/iccp"
	"github.com/unix4fun/ic/ickp"
	"github.com/unix4fun/ic/icutl"
	"time"
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
	icutl.DebugLog.Printf("CALL [%p] Validate(%d))\n", pk, pk.Type)

	if len(pk.Server) > 0 { // as Server information is needed by all requests
		switch pk.Type {
		case PKGEN:
			if len(pk.Nick) > 0 {
				icutl.DebugLog.Printf("RET [%p] Validate() -> PKGEN OK\n", pk)
				return nil
			}
		case PKADD:
			if len(pk.Nick) > 0 && len(pk.Blob) > 0 {
				icutl.DebugLog.Printf("RET [%p] Validate() -> PKADD OK\n", pk)
				return nil
			}
		case PKLIST:
			icutl.DebugLog.Printf("RET [%p] Validate() -> PKLIST OK\n", pk)
			return nil
		case PKDEL:
			if len(pk.Nick) > 0 {
				icutl.DebugLog.Printf("RET [%p] Validate() -> PKDEL OK\n", pk)
				return nil
			}
		} // end of switch
	} // end of if

	icutl.DebugLog.Printf("RET [%p] Validate(%d) -> [Error: Invalid PK message]\n", pk, pk.Type)
	return fmt.Errorf("Invalid PK[%d] message!\n", pk.Type)
}

func (pk *ACPkMessage) HandlerPKGEN() (msgReply []byte, err error) {
	icutl.DebugLog.Printf("CALL [%p] HandlePKGEN(%d:%s/%s)\n", pk, pk.Type, pk.Server, pk.Nick)

	err = pk.validate()
	if err != nil {
		msgReply, _ = json.Marshal(&ACPkReply{
			Type:  R_PKGEN,
			Bada:  false,
			Errno: -1,
			Blob:  []byte(err.Error()),
		})
		icutl.DebugLog.Printf("RET [%p] HandlePKGEN(%d:%s/%s) -> [Error: %s]\n", pk, pk.Type, pk.Server, pk.Nick, err.Error())
		return
	}

	myNewKeys, err := ickp.CreateKxKeys(pk.Nick, pk.Host, pk.Server)
	if err != nil {
		msgReply, _ = json.Marshal(&ACPkReply{
			Type:  R_PKGEN,
			Bada:  false,
			Errno: -2,
			Blob:  []byte(err.Error()),
		})
		icutl.DebugLog.Printf("RET [%p] HandlePKGEN(%d:%s/%s) -> [Error: %s]\n", pk, pk.Type, pk.Server, pk.Nick, err.Error())
		return
	}
	// create the cached version instead of in CreateMyKeys()
	PK, err := iccp.CreatePKMessageNACL(myNewKeys.GetPubkey()[:])
	if err != nil {
		msgReply, _ = json.Marshal(&ACPkReply{
			Type:  R_PKGEN,
			Bada:  false,
			Errno: -3,
			Blob:  []byte(err.Error()),
		})
		icutl.DebugLog.Printf("RET [%p] HandlePKGEN(%d:%s/%s) -> [Error: %s]\n", pk, pk.Type, pk.Server, pk.Nick, err.Error())
		return
	}
	myNewKeys.Pubkey = string(PK)

	// create the Public Key storage if it's empty...
	ickp.ACmap.SetPKMapEntry(pk.Server, pk.Nick, myNewKeys)

	// all good we return the data
	msgReply, _ = json.Marshal(&ACPkReply{
		Type:  R_PKGEN,
		Bada:  true,
		Errno: 0,
	})
	icutl.DebugLog.Printf("RET [%p] HandlePKGEN(%d:%s/%s) -> [reply: %s]\n", pk, pk.Type, pk.Server, pk.Nick, msgReply)
	return
}

//
// HandlerPKADD is the final handler for PKADD control messages
func (pk *ACPkMessage) HandlerPKADD() (msgReply []byte, err error) {
	icutl.DebugLog.Printf("CALL [%p] HandlePKADD(%d:%s/%s)\n", pk, pk.Type, pk.Server, pk.Nick)

	err = pk.validate()
	if err != nil {
		msgReply, _ = json.Marshal(&ACPkReply{
			Type:  R_PKADD,
			Bada:  false,
			Errno: -1,
			Blob:  []byte(err.Error()),
		})
		icutl.DebugLog.Printf("RET [%p] HandlePKADD(%d:%s/%s) -> [Error: %s]\n", pk, pk.Type, pk.Server, pk.Nick, err.Error())
		return
	}

	//
	newkey := new(ickp.KexKey)
	newkey.Nickname = pk.Nick
	newkey.Userhost = pk.Host
	newkey.Server = pk.Server
	newkey.Pubkey = string(pk.Blob)
	newkey.HasPriv = false
	newkey.CreaTime = time.Now()
	newkey.Timestamp = newkey.CreaTime.Unix()

	pubk, err := iccp.OpenPKMessageNACL([]byte(pk.Blob))
	if err != nil {
		msgReply, _ = json.Marshal(&ACPkReply{
			Type:  R_PKADD,
			Bada:  false,
			Errno: -2,
			Blob:  []byte(err.Error()),
		})
		icutl.DebugLog.Printf("RET [%p] HandlePKADD(%d:%s/%s) -> [Error: %s]\n", pk, pk.Type, pk.Server, pk.Nick, err.Error())
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
		icutl.DebugLog.Printf("RET [%p] HandlePKADD(%d:%s/%s) -> [Error: %s]\n", pk, pk.Type, pk.Server, pk.Nick, err.Error())
		return
	}

	ickp.ACmap.SetPKMapEntry(pk.Server, pk.Nick, newkey)

	// all good we return the data
	msgReply, _ = json.Marshal(&ACPkReply{
		Type:  R_PKADD,
		Bada:  true,
		Errno: 0,
	})
	icutl.DebugLog.Printf("RET [%p] HandlePKADD(%d:%s/%s) -> [reply: %s]\n", pk, pk.Type, pk.Server, pk.Nick, msgReply)
	return
}

func (pk *ACPkMessage) HandlerPKLIST() (msgReply []byte, err error) {
	icutl.DebugLog.Printf("CALL [%p] HandlePKLIST(%d:%s/%s)\n", pk, pk.Type, pk.Server, pk.Nick)

	err = pk.validate()
	if err != nil {
		msgReply, _ = json.Marshal(&ACPkReply{
			Type:  R_PKLIST,
			Bada:  false,
			Errno: -1,
			Blob:  []byte(err.Error()),
		})
		icutl.DebugLog.Printf("RET [%p] HandlePKADD(%d:%s/%s) -> [Error: %s]\n", pk, pk.Type, pk.Server, pk.Nick, err.Error())
		return
	}

	pkMap, okMap := ickp.ACmap.GetPKMap(pk.Server)
	//pkEntry, okEnt := ickp.ACmap.GetPKMapEntry(pk.Server, pk.Nick)

	// we have one entry for the request
	icutl.DebugLog.Printf("ok_map: %t\n", okMap)
	if okMap == true {
		icutl.DebugLog.Printf("ok_map len: %d\n", len(*pkMap))

		// KISS: we always return all keys... the script will parse what it needs. :)
		msgReplyBlob, rErr := json.Marshal(*pkMap)
		if rErr != nil {
			panic(rErr)
		}

		icutl.DebugLog.Printf("(INFO) PKLIST -> (Blob: %s) ! n Keys\n", msgReplyBlob)
		msgReply, _ = json.Marshal(&ACPkReply{
			Type:  R_PKLIST,
			Bada:  true,
			Errno: 0,
			Blob:  msgReplyBlob,
		})
		return
	}
	msgReply, _ = json.Marshal(&ACPkReply{
		Type:  R_PKLIST,
		Bada:  true,
		Errno: 0,
		Blob:  nil,
	})
	icutl.DebugLog.Printf("RET [%p] HandlePKLIST(%d:%s/%s) -> [reply: %s]\n", pk, pk.Type, pk.Server, pk.Nick)
	return
}

func (pk *ACPkMessage) HandlerPKDEL() (msgReply []byte, err error) {
	icutl.DebugLog.Printf("CALL [%p] HandlePKDEL(%d:%s/%s)\n", pk, pk.Type, pk.Server, pk.Nick)
	delErr := 0

	err = pk.validate()
	if err != nil {
		msgReply, _ = json.Marshal(&ACPkReply{
			Type:  R_PKDEL,
			Bada:  false,
			Errno: -1,
			Blob:  []byte(err.Error()),
		})
		icutl.DebugLog.Printf("RET [%p] HandlePKDEL(%d:%s/%s) -> [Error: %s]\n", pk, pk.Type, pk.Server, pk.Nick, err.Error())
		return
	}

	// ahah we actually need to delete the key :)
	delOk := ickp.ACmap.DelPKMapEntry(pk.Server, pk.Nick)
	if delOk == false {
		delErr = 1
	}

	// all good we return the data
	msgReply, _ = json.Marshal(&ACPkReply{
		Type:  R_PKDEL,
		Bada:  true,
		Errno: delErr, // return 0 if deleted successfully, return 1 if the nick was not present.
	})
	icutl.DebugLog.Printf("RET [%p] HandlePKDEL(%d:%s/%s) -> [reply: %s]\n", pk, pk.Type, pk.Server, pk.Nick)
	return
}

//
//
// Handle PUBLIC KEY MESSAGES..
//
//
func HandlePKMsg(msg []byte) (msgReply []byte, err error) {
	icutl.DebugLog.Printf("CALL HandlePKMsg(msg[%d]:[%s])\n", len(msg), msg)
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
		icutl.DebugLog.Printf("RET HandlerPKMsg(%s) -> [Error: %s]\n", msg, msgReply)
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

	icutl.DebugLog.Printf("RET HandlePKMsg(msg[%d]:[%s]) -> [reply[%d]: %s]\n", len(msg), msg, len(msgReply), msgReply)
	return
}
