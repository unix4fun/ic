package acjs

import (
	"encoding/json"
	"fmt"
	"github.com/unix4fun/ac/ackp"
	"github.com/unix4fun/ac/acutl"
)

type ACClMessage struct {
	Type    int    `json:"type"`
	Channel string `json:"channel"`
	Server  string `json:"server"`
	Blob    []byte `json:"blob"`
}

type ACClReply struct {
	Type  int    `json:"type"`
	Bada  bool   `json:"bada"`
	Errno int    `json:"errno"`
	Blob  []byte `json:"blob,omitempty"`
}

func (cl *ACClMessage) validate() error {
	acutl.DebugLog.Printf("CALL [%p] Validate(%d))\n", cl, cl.Type)
	switch cl.Type {
	case CLLOAD:
		if len(cl.Blob) > 0 {
			return nil
		}
	case CLSAVE:
		if len(cl.Blob) > 0 {
			return nil
		}
	case CLIAC:
		if len(cl.Server) > 0 && len(cl.Channel) > 0 {
			return nil
		}

	} // end of switch..

	acutl.DebugLog.Printf("RET [%p] Validate(%d) -> [Error: Invalid CL message]\n", cl, cl.Type)
	return fmt.Errorf("Invalid CL[%d] message!\n", cl.Type)
}

func (cl *ACClMessage) HandlerCLLOAD() (msgReply []byte, err error) {
	acutl.DebugLog.Printf("CALL [%p] HandlerCLLOAD([%d/%s/%s]: p:%02s)\n",
		cl,
		cl.Type,
		cl.Server,
		cl.Channel,
		cl.Blob)

	err = cl.validate()
	if err != nil {
		msgReply, _ = json.Marshal(&ACClReply{
			Type:  R_CLLOAD,
			Bada:  false,
			Errno: -1,
			Blob:  []byte(err.Error()),
		})
		acutl.DebugLog.Printf("RET [%p] HandlerCLLOAD([%d/%s/%s]: p:%02s) -> [Error: %s]\n",
			cl,
			cl.Type,
			cl.Server,
			cl.Channel,
			cl.Blob, err.Error())
		return
	}

	ok, err := ackp.ACmap.File2Map(ackp.AcSaveFile, []byte(cl.Blob))
	if err != nil || ok != true {
		msgReply, _ = json.Marshal(&ACClReply{
			Type:  R_CLLOAD,
			Bada:  false,
			Errno: -2,
			Blob:  []byte(err.Error()),
		})
		acutl.DebugLog.Printf("RET [%p] HandlerCLLOAD([%d/%s/%s]: p:%02s) -> [Error: %s]\n",
			cl,
			cl.Type,
			cl.Server,
			cl.Channel,
			cl.Blob, err.Error())
		return
	}

	msgReply, _ = json.Marshal(&ACClReply{
		Type:  R_CLLOAD,
		Bada:  true,
		Errno: 0,
	})
	acutl.DebugLog.Printf("RET [%p] HandlerCLLOAD([%d/%s/%s]: p:%02s) -> [OK]\n",
		cl,
		cl.Type,
		cl.Server,
		cl.Channel,
		cl.Blob)
	return
}

func (cl *ACClMessage) HandlerCLSAVE() (msgReply []byte, err error) {
	acutl.DebugLog.Printf("CALL [%p] HandlerCLSAVE([%d/%s/%s]: p:%02s)\n",
		cl,
		cl.Type,
		cl.Server,
		cl.Channel,
		cl.Blob)

	err = cl.validate()
	if err != nil {
		msgReply, _ = json.Marshal(&ACClReply{
			Type:  R_CLSAVE,
			Bada:  false,
			Errno: -1,
			Blob:  []byte(err.Error()),
		})
		acutl.DebugLog.Printf("RET [%p] HandlerCLSAVE([%d/%s/%s]: p:%02s) -> [Error: %s]\n",
			cl,
			cl.Type,
			cl.Server,
			cl.Channel,
			cl.Blob, err.Error())
		return
	}

	//func (psk PSKMap) Map2FileBlob(outfilestr string, salt []byte, keystr []byte) (bool, error) {
	// TODO: we hardcode the save file
	ok, err := ackp.ACmap.Map2File(ackp.AcSaveFile, []byte(cl.Blob))
	if err != nil || ok != true {
		msgReply, _ = json.Marshal(&ACClReply{
			Type:  R_CLSAVE,
			Bada:  false,
			Errno: -1,
			Blob:  []byte(err.Error()),
		})
		acutl.DebugLog.Printf("RET [%p] HandlerCLSAVE([%d/%s/%s]: p:%02s) -> [Error: %s]\n",
			cl,
			cl.Type,
			cl.Server,
			cl.Channel,
			cl.Blob, err.Error())
		return
	}

	msgReply, _ = json.Marshal(&ACClReply{
		Type:  R_CLSAVE,
		Bada:  true,
		Errno: 0,
	})
	acutl.DebugLog.Printf("RET [%p] HandlerCLSAVE([%d/%s/%s]: p:%02s) -> [OK]\n",
		cl,
		cl.Type,
		cl.Server,
		cl.Channel,
		cl.Blob)
	return
}

func (cl *ACClMessage) HandlerCLIAC() (msgReply []byte, err error) {
	acutl.DebugLog.Printf("CALL [%p] HandlerCLIAC([%d/%s/%s]: p:%02s)\n",
		cl,
		cl.Type,
		cl.Server,
		cl.Channel,
		cl.Blob)

	err = cl.validate()
	if err != nil {
		msgReply, _ = json.Marshal(&ACClReply{
			Type:  R_CLIAC,
			Bada:  false,
			Errno: -1,
			Blob:  []byte(err.Error()),
		})
		acutl.DebugLog.Printf("RET [%p] HandlerCLIAC([%d/%s/%s]: p:%02s) -> [Error: %s]\n",
			cl,
			cl.Type,
			cl.Server,
			cl.Channel,
			cl.Blob, err.Error())
		return
	}

	_, ok_a := ackp.ACmap.GetSKMapEntry(cl.Server, cl.Channel)
	_, ok_b := ackp.ACmap.GetRDMapEntry(cl.Server, cl.Channel)
	if ok_a == false || ok_b == false {
		err = fmt.Errorf("no map for this server/channel combo")
		msgReply, _ = json.Marshal(&ACClReply{
			Type:  R_CLIAC,
			Bada:  false,
			Errno: -2,
			Blob:  []byte(err.Error()),
		})
		acutl.DebugLog.Printf("RET [%p] HandlerCLIAC([%d/%s/%s]: p:%02s) -> [Error: %s]\n",
			cl,
			cl.Type,
			cl.Server,
			cl.Channel,
			cl.Blob, err.Error())
		return
	}

	msgReply, _ = json.Marshal(&ACClReply{
		Type:  R_CLIAC,
		Bada:  true,
		Errno: 0,
	})
	acutl.DebugLog.Printf("RET [%p] HandlerCLIAC([%d/%s/%s]: p:%02s) -> [OK]\n",
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
	acutl.DebugLog.Printf("CALL HandleCLMsg(msg[%d]:[%s])\n", len(msg), msg)
	req := &ACClMessage{}

	// let's unmarshall the message first
	err = json.Unmarshal(msg, req)
	if err != nil {
		acutl.DebugLog.Printf("RET HandlerCtMsg(%s) -> [Error: %s]\n", msg, err.Error())
		msgReply, _ = json.Marshal(&ACClReply{
			Type:  R_CLERR,
			Bada:  false,
			Errno: -1,
			Blob:  []byte(err.Error()),
		})
		return
	}

	switch req.Type {
	case CLLOAD:
		msgReply, err = req.HandlerCLLOAD()
	case CLSAVE:
		msgReply, err = req.HandlerCLSAVE()
	case CLIAC:
		msgReply, err = req.HandlerCLIAC()
	default:
		err = fmt.Errorf("Invalid CL Message.")
		msgReply, _ = json.Marshal(&ACClReply{
			Type:  R_CLERR,
			Bada:  false,
			Errno: -2,
			Blob:  []byte(err.Error()),
		})
	}

	acutl.DebugLog.Printf("RET HandleCLMsg(msg[%d]:[%s]) -> [reply[%d]: %s]\n", len(msg), msg, len(msgReply), msgReply)
	return
}
