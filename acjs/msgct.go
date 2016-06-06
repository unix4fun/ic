package acjs

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/unix4fun/ac/accp"
	"github.com/unix4fun/ac/ackp"
	"github.com/unix4fun/ac/acutl"
	"io"
)

type ACCtMessage struct {
	Type    int    `json:"type"`
	Nick    string `json:"nick"`
	Server  string `json:"server"`
	Channel string `json:"channel"`
	Blob    []byte `json:"blob"`
	Opt     []byte `json:"opt"`
}

type ACCtReply struct {
	Type   int      `json:"type"`
	Bada   bool     `json:"bada"`
	Errno  int      `json:"errno"`
	Blob   []byte   `json:"blob"`
	Barray [][]byte `json:"blobarray,omitempty"`
	Nonce  uint32   `json:"nonce"`
}

func (ct *ACCtMessage) validate() error {
	acutl.DebugLog.Printf("CALL [%p] Validate(%d))\n", ct, ct.Type)
	if (len(ct.Nick) > 0) && (len(ct.Server) > 0) && (len(ct.Channel) > 0) {
		switch ct.Type {
		case CTSEAL:
			if len(ct.Blob) > 0 {
				return nil
			}
		case CTOPEN:
			if len(ct.Blob) > 6 && len(ct.Opt) > 0 {
				return nil
			}
		case CTADD:
			return nil

		} // end of switch..
	} // end of if...

	acutl.DebugLog.Printf("RET [%p] Validate(%d) -> [Error: Invalid KX message]\n", ct, ct.Type)
	return fmt.Errorf("Invalid KX[%d] message!\n", ct.Type)
}

func (ct *ACCtMessage) HandlerCTSEAL() (msgReply []byte, err error) {
	//var acctx *ackp.SecretKey
	var acBlobArray [][]byte
	var out []byte
	var reqBlobTmp []byte

	acutl.DebugLog.Printf("CALL [%p] HandlerCTSEAL([%d/%s/%s] <%s> %08s)\n",
		ct,
		ct.Type,
		ct.Server,
		ct.Channel,
		ct.Nick,
		ct.Blob)

	err = ct.validate()
	if err != nil {
		msgReply, _ = json.Marshal(&ACCtReply{
			Type:  R_CTSEAL,
			Bada:  false,
			Errno: -1,
			Blob:  []byte(err.Error()),
		})
		acutl.DebugLog.Printf("RET [%p] HandlerCTSEAL([%d/%s/%s] <%s> %04s) -> [Error: %s]\n",
			ct,
			ct.Type,
			ct.Server,
			ct.Channel,
			ct.Nick,
			ct.Blob, err.Error())
		return
	}

	acctx, ok_a := ackp.ACmap.GetSKMapEntry(ct.Server, ct.Channel)
	acrnd, ok_b := ackp.ACmap.GetRDMapEntry(ct.Server, ct.Channel)

	if ok_a == false || ok_b == false {
		err = fmt.Errorf("No key/Corrupted key/rnd map")
		msgReply, _ = json.Marshal(&ACCtReply{
			Type:  R_CTSEAL,
			Bada:  false,
			Errno: -2,
			Blob:  []byte(err.Error()),
		})
		return
	}

	// XXX test here for message length and send multiple encrypted messages
	// TODO: dont hardcode the limits but well it's a first try
	// back if the original message is too long.
	/*
		if len(out)+14+len(reqChan) > 512 {
			fmt.Fprintf(os.Stderr, "MESSAGE WAYYYYYY TOO LONG LET's SPLIT AND BUILD SEVERAL")
		}
	*/
	//tmpBlobLen := len(reqBlob)
	//:nick!user@host PRIVMSG target :<usable bytes><CRLF>
	msgLen := accp.PredictLenNACL(ct.Blob) + len(ct.Channel) + 14
	nBlock := msgLen/410 + 1

	// BUG HERE with offsets...
	for j, bSize, bAll, bPtr := 0, len(ct.Blob)/nBlock, len(ct.Blob), 0; j < nBlock; j, bPtr = j+1, bPtr+bSize {
		if bPtr+bSize+1 >= bAll {
			reqBlobTmp = ct.Blob[bPtr:]
			//fmt.Fprintf(os.Stderr, "** %d block[%d:%d]: %s \n", j, bPtr, bAll, reqBlobTmp)
			//fmt.Fprintf(os.Stderr, ">> %d => %c || %d => %c\n", bAll, reqBlob[bAll-1], bAll+1, reqBlob[bAll+1])
			//reqBlob[bPtr:bAll]
		} else {
			reqBlobTmp = ct.Blob[bPtr : bPtr+bSize]
			//fmt.Fprintf(os.Stderr, ">>#%d block[%d:%d]: %s \n", j, bPtr, bPtr+bSize, reqBlobTmp)
			//reqBlob[bPtr : bPtr+bSize]
		} // END OF ELSE

		//fmt.Fprintf(os.Stderr, ">> NEW #%d block[%d:%d]: %s \n", j, bPtr, bPtr+len(reqBlobTmp), reqBlobTmp)
		out, err = accp.CreateACMessageNACL(acctx, acrnd, reqBlobTmp, []byte(ct.Nick))
		if err != nil {
			msgReply, _ = json.Marshal(&ACCtReply{
				Type:  R_CTSEAL,
				Bada:  false,
				Errno: -3,
				Blob:  []byte(err.Error()),
			})
			return
		}
		acBlobArray = append(acBlobArray, out)
	} // END OF FOR

	msgReply, _ = json.Marshal(&ACCtReply{
		Type:   R_CTSEAL,
		Bada:   true,
		Errno:  0,
		Nonce:  acctx.GetNonce(),
		Barray: acBlobArray,
	})
	acutl.DebugLog.Printf("RET [%p] HandlerCTSEAL([%d/%s/%s] <%s> %04s) -> [OK:%04s]\n",
		ct,
		ct.Type,
		ct.Server,
		ct.Channel,
		ct.Nick,
		ct.Blob,
		acBlobArray)
	return
}

func (ct *ACCtMessage) HandlerCTOPEN() (msgReply []byte, err error) {
	acutl.DebugLog.Printf("CALL [%p] HandlerCTOPEN([%d/%s/%s] <= <%s> %08s)\n",
		ct,
		ct.Type,
		ct.Server,
		ct.Channel,
		ct.Nick,
		ct.Blob)
	////
	err = ct.validate()
	if err != nil {
		msgReply, _ = json.Marshal(&ACCtReply{
			Type:  R_CTOPEN,
			Bada:  false,
			Errno: -1,
			Blob:  []byte(err.Error()),
		})
		acutl.DebugLog.Printf("RET [%p] HandlerCTSEAL([%d/%s/%s] <%s> %04s) -> [Error: %s]\n",
			ct,
			ct.Type,
			ct.Server,
			ct.Channel,
			ct.Nick,
			ct.Blob, err.Error())
		return
	}

	//acctx, ok_a := Sk[channel]
	acctx, ok_a := ackp.ACmap.GetSKMapEntry(ct.Server, ct.Channel)
	acrnd, ok_b := ackp.ACmap.GetRDMapEntry(ct.Server, ct.Channel)

	if ok_a == false || ok_b == false {
		err = fmt.Errorf("CTOPEN_Handler(): no SKMap/RDMap Entry found!")
		msgReply, _ = json.Marshal(&ACCtReply{
			Type:  R_CTOPEN,
			Bada:  false,
			Errno: -2,
			Blob:  []byte(err.Error()),
		})
		return
	}

	//func OpenACMessage(context * SecKey, cmsg, peerNick []byte) (out []byte, err error) {
	// XXX TODO: use reqOpt accordingly
	out, err := accp.OpenACMessageNACL(acctx, acrnd, ct.Blob, []byte(ct.Nick), []byte(ct.Opt))
	if err != nil {
		//err = fmt.Errorf("CTOPEN_Handler(): OpenACMessageNACL() error")
		msgReply, _ = json.Marshal(&ACCtReply{
			Type:  R_CTOPEN,
			Bada:  false,
			Errno: -3,
			Blob:  []byte(err.Error()),
		})
		return
	}

	msgReply, _ = json.Marshal(&ACCtReply{
		Type:  R_CTOPEN,
		Bada:  true,
		Errno: 0,
		Nonce: acctx.GetNonce(),
		Blob:  []byte(out),
	})

	acutl.DebugLog.Printf("RET [%p] HandlerCTOPEN([%d/%s/%s] <%s> %08s) -> [OK]\n",
		ct,
		ct.Type,
		ct.Server,
		ct.Channel,
		ct.Nick,
		ct.Blob)
	return
}

func (ct *ACCtMessage) HandlerCTADD() (msgReply []byte, err error) {
	acutl.DebugLog.Printf("CALL [%p] HandlerCTADD([%d/%s/%s] <%s> %08s)\n",
		ct,
		ct.Type,
		ct.Server,
		ct.Channel,
		ct.Nick,
		ct.Blob)

	err = ct.validate()
	if err != nil {
		msgReply, _ = json.Marshal(&ACCtReply{
			Type:  R_CTADD,
			Bada:  false,
			Errno: -1,
			Blob:  []byte(err.Error()),
		})
		acutl.DebugLog.Printf("RET [%p] HandlerCTADD([%d/%s/%s] <%s> %04s) -> [Error: %s]\n",
			ct,
			ct.Type,
			ct.Server,
			ct.Channel,
			ct.Nick,
			ct.Blob, err.Error())
		return
	}

	// lets derive the key.
	//    randsalt :=  rand.Read()
	//    func (skgen ACSecretKeyGen) Init(input []byte, channel []byte, nick []byte, serv []byte) {
	skgen := new(ackp.KeyGenerator)
	err = skgen.Init([]byte(ct.Blob), []byte(ct.Channel), []byte(ct.Nick), []byte(ct.Server))
	if err != nil {
		msgReply, _ = json.Marshal(&ACCtReply{
			Type:  R_CTADD,
			Bada:  false,
			Errno: -2,
			Blob:  []byte(err.Error()),
		})
		acutl.DebugLog.Printf("RET [%p] HandlerCTADD([%d/%s/%s] <%s> %04s) -> [Error: %s]\n",
			ct,
			ct.Type,
			ct.Server,
			ct.Channel,
			ct.Nick,
			ct.Blob, err.Error())
		return
	}

	// XXX TODO: handle error or remove it...
	acctx, _ := ackp.CreateACContext([]byte(ct.Channel), 0)

	key := make([]byte, 32)
	io.ReadFull(skgen, key)

	newRnd := make([]byte, len(key))
	_, err = rand.Read(newRnd)
	if err != nil {
		msgReply, _ = json.Marshal(&ACCtReply{
			Type:  R_CTADD,
			Bada:  false,
			Errno: -3,
			Blob:  []byte(err.Error()),
		})
		acutl.DebugLog.Printf("RET [%p] HandlerCTADD([%d/%s/%s] <%s> %04s) -> [Error: %s]\n",
			ct,
			ct.Type,
			ct.Server,
			ct.Channel,
			ct.Nick,
			ct.Blob, err.Error())
		return
	}

	acctx.SetKey(key)
	// XOR the key...
	acctx.RndKey(newRnd)

	ackp.ACmap.SetSKMapEntry(ct.Server, ct.Channel, acctx)
	ackp.ACmap.SetRDMapEntry(ct.Server, ct.Channel, newRnd)

	msgReply, _ = json.Marshal(&ACCtReply{
		Type:  R_CTADD,
		Bada:  true,
		Errno: 0,
		Blob:  []byte("OK"),
	})
	acutl.DebugLog.Printf("RET [%p] HandlerCTADD([%d/%s/%s] <%s> %04s) -> [OK]\n",
		ct,
		ct.Type,
		ct.Server,
		ct.Channel,
		ct.Nick,
		ct.Blob)
	return
}

//
//
// Handle Crypto MESSAGES..
//
//
func HandleCTMsg(msg []byte) (msgReply []byte, err error) {
	acutl.DebugLog.Printf("CALL HandleCTMsg(msg[%d]:[%s])\n", len(msg), msg)
	req := &ACCtMessage{}

	// let's unmarshall the message first
	err = json.Unmarshal(msg, req)
	if err != nil {
		acutl.DebugLog.Printf("RET HandlerCtMsg(%s) -> [Error: %s]\n", msg, err.Error())
		msgReply, _ = json.Marshal(&ACCtReply{
			Type:  R_CTERR,
			Bada:  false,
			Errno: -1,
			Blob:  []byte(err.Error()),
		})
		return
	}

	switch req.Type {
	case CTSEAL:
		msgReply, err = req.HandlerCTSEAL()
	case CTOPEN:
		msgReply, err = req.HandlerCTOPEN()
	case CTADD:
		msgReply, err = req.HandlerCTADD()
	default:
		err = fmt.Errorf("Invalid CT Message.")
		msgReply, _ = json.Marshal(&ACCtReply{
			Type:  R_CTERR,
			Bada:  false,
			Errno: -2,
			Blob:  []byte(err.Error()),
		})
	}

	acutl.DebugLog.Printf("RET HandleCTMsg(msg[%d]:[%s]) -> [reply[%d]: %s]\n", len(msg), msg, len(msgReply), msgReply)
	return
}
