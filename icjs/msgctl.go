// +build go1.5

package icjs

import (
	"encoding/json"
	"fmt"
	"github.com/unix4fun/ic/ickp"
	"github.com/unix4fun/ic/icutl"
)

type ACClMessage struct {
	Type    int    `json:"type"`
	Channel string `json:"channel"`
	Server  string `json:"server"`
	Blob    string `json:"blob"`
}

type ACClReply struct {
	Type  int    `json:"type"`
	Bada  bool   `json:"bada"`
	Errno int    `json:"errno"`
	Blob  string `json:"blob,omitempty"`
}

func (cl *ACClMessage) validate() error {
	icutl.DebugLog.Printf("CALL [%p] Validate(%d))\n", cl, cl.Type)
	switch cl.Type {
	case clLoad:
		if len(cl.Blob) > 0 {
			return nil
		}
	case clSave:
		if len(cl.Blob) > 0 {
			return nil
		}
	case clIsAC:
		if len(cl.Server) > 0 && len(cl.Channel) > 0 {
			return nil
		}

	} // end of switch..

	icutl.DebugLog.Printf("RET [%p] Validate(%d) -> [Error: Invalid CL message]\n", cl, cl.Type)
	return fmt.Errorf("invalid CL[%d] message", cl.Type)
}

func (cl *ACClMessage) HandlerCLLOAD() (msgReply []byte, err error) {
	icutl.DebugLog.Printf("CALL [%p] HandlerCLLOAD([%d/%s/%s]: p:%02s)\n",
		cl,
		cl.Type,
		cl.Server,
		cl.Channel,
		cl.Blob)

	err = cl.validate()
	if err != nil {
		msgReply, _ = json.Marshal(&ACClReply{
			Type:  clLoadReply,
			Bada:  false,
			Errno: -1,
			Blob:  err.Error(),
		})
		icutl.DebugLog.Printf("RET [%p] HandlerCLLOAD([%d/%s/%s]: p:%02s) -> [Error: %s]\n",
			cl,
			cl.Type,
			cl.Server,
			cl.Channel,
			cl.Blob, err.Error())
		return
	}

	ok, err := ickp.ACmap.File2Map(ickp.AcSaveFile, []byte(cl.Blob))
	if err != nil || ok != true {
		msgReply, _ = json.Marshal(&ACClReply{
			Type:  clLoadReply,
			Bada:  false,
			Errno: -2,
			Blob:  err.Error(),
		})
		icutl.DebugLog.Printf("RET [%p] HandlerCLLOAD([%d/%s/%s]: p:%02s) -> [Error: %s]\n",
			cl,
			cl.Type,
			cl.Server,
			cl.Channel,
			cl.Blob, err.Error())
		return
	}

	msgReply, _ = json.Marshal(&ACClReply{
		Type:  clLoadReply,
		Bada:  true,
		Errno: 0,
	})
	icutl.DebugLog.Printf("RET [%p] HandlerCLLOAD([%d/%s/%s]: p:%02s) -> [OK]\n",
		cl,
		cl.Type,
		cl.Server,
		cl.Channel,
		cl.Blob)
	return
}

func (cl *ACClMessage) HandlerCLSAVE() (msgReply []byte, err error) {
	icutl.DebugLog.Printf("CALL [%p] HandlerCLSAVE([%d/%s/%s]: p:%02s)\n",
		cl,
		cl.Type,
		cl.Server,
		cl.Channel,
		cl.Blob)

	err = cl.validate()
	if err != nil {
		msgReply, _ = json.Marshal(&ACClReply{
			Type:  clSaveReply,
			Bada:  false,
			Errno: -1,
			Blob:  err.Error(),
		})
		icutl.DebugLog.Printf("RET [%p] HandlerCLSAVE([%d/%s/%s]: p:%02s) -> [Error: %s]\n",
			cl,
			cl.Type,
			cl.Server,
			cl.Channel,
			cl.Blob, err.Error())
		return
	}

	//func (psk PSKMap) Map2FileBlob(outfilestr string, salt []byte, keystr []byte) (bool, error) {
	// TODO: we hardcode the save file
	ok, err := ickp.ACmap.Map2File(ickp.AcSaveFile, []byte(cl.Blob))
	if err != nil || ok != true {
		msgReply, _ = json.Marshal(&ACClReply{
			Type:  clSaveReply,
			Bada:  false,
			Errno: -1,
			Blob:  err.Error(),
		})
		icutl.DebugLog.Printf("RET [%p] HandlerCLSAVE([%d/%s/%s]: p:%02s) -> [Error: %s]\n",
			cl,
			cl.Type,
			cl.Server,
			cl.Channel,
			cl.Blob, err.Error())
		return
	}

	msgReply, _ = json.Marshal(&ACClReply{
		Type:  clSaveReply,
		Bada:  true,
		Errno: 0,
	})
	icutl.DebugLog.Printf("RET [%p] HandlerCLSAVE([%d/%s/%s]: p:%02s) -> [OK]\n",
		cl,
		cl.Type,
		cl.Server,
		cl.Channel,
		cl.Blob)
	return
}

func (cl *ACClMessage) HandlerCLIAC() (msgReply []byte, err error) {
	icutl.DebugLog.Printf("CALL [%p] HandlerCLIAC([%d/%s/%s]: p:%02s)\n",
		cl,
		cl.Type,
		cl.Server,
		cl.Channel,
		cl.Blob)

	err = cl.validate()
	if err != nil {
		msgReply, _ = json.Marshal(&ACClReply{
			Type:  clIsACReply,
			Bada:  false,
			Errno: -1,
			Blob:  err.Error(),
		})
		icutl.DebugLog.Printf("RET [%p] HandlerCLIAC([%d/%s/%s]: p:%02s) -> [Error: %s]\n",
			cl,
			cl.Type,
			cl.Server,
			cl.Channel,
			cl.Blob, err.Error())
		return
	}

	_, ok_a := ickp.ACmap.GetSKMapEntry(cl.Server, cl.Channel)
	_, ok_b := ickp.ACmap.GetRDMapEntry(cl.Server, cl.Channel)
	if ok_a == false || ok_b == false {
		err = fmt.Errorf("no map for this server/channel combo")
		msgReply, _ = json.Marshal(&ACClReply{
			Type:  clIsACReply,
			Bada:  false,
			Errno: -2,
			Blob:  err.Error(),
		})
		icutl.DebugLog.Printf("RET [%p] HandlerCLIAC([%d/%s/%s]: p:%02s) -> [Error: %s]\n",
			cl,
			cl.Type,
			cl.Server,
			cl.Channel,
			cl.Blob, err.Error())
		return
	}

	msgReply, _ = json.Marshal(&ACClReply{
		Type:  clIsACReply,
		Bada:  true,
		Errno: 0,
	})
	icutl.DebugLog.Printf("RET [%p] HandlerCLIAC([%d/%s/%s]: p:%02s) -> [OK]\n",
		cl,
		cl.Type,
		cl.Server,
		cl.Channel,
		cl.Blob)
	return
}

//
//
// Handle Control MESSAGES..
//
//
func HandleCLMsg(msg []byte) (msgReply []byte, err error) {
	icutl.DebugLog.Printf("CALL HandleCLMsg(msg[%d]:[%s])\n", len(msg), msg)
	req := &ACClMessage{}

	// let's unmarshall the message first
	err = json.Unmarshal(msg, req)
	if err != nil {
		icutl.DebugLog.Printf("RET HandlerCtMsg(%s) -> [Error: %s]\n", msg, err.Error())
		msgReply, _ = json.Marshal(&ACClReply{
			Type:  clErrReply,
			Bada:  false,
			Errno: -1,
			Blob:  err.Error(),
		})
		return
	}

	switch req.Type {
	case clLoad:
		msgReply, err = req.HandlerCLLOAD()
	case clSave:
		msgReply, err = req.HandlerCLSAVE()
	case clIsAC:
		msgReply, err = req.HandlerCLIAC()
	default:
		err = fmt.Errorf("invalid CL message")
		msgReply, _ = json.Marshal(&ACClReply{
			Type:  clErrReply,
			Bada:  false,
			Errno: -2,
			Blob:  err.Error(),
		})
	}

	icutl.DebugLog.Printf("RET HandleCLMsg(msg[%d]:[%s]) -> [reply[%d]: %s]\n", len(msg), msg, len(msgReply), msgReply)
	return
}
