// +build go1.5

package icjs

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/unix4fun/ic/iccp"
	"github.com/unix4fun/ic/ickp"
	"github.com/unix4fun/ic/icutl"
	"io"
)

const (
	IRCMSG_MAXSIZE = 512
	IRCMSG_PREFIX  = "PRIVMSG  : " // that's what it should containt
	IRCMSG_SUFFIX  = "\r\n"
)

type ACCtMessage struct {
	Type    int    `json:"type"`
	Nick    string `json:"nick"`
	Server  string `json:"server"`
	Channel string `json:"channel"`
	Blob    string `json:"blob"`
	Opt     string `json:"opt"`
	//Blob    []byte `json:"blob"`
	//Opt     []byte `json:"opt"`
}

type ACCtReply struct {
	Type   int      `json:"type"`
	Bada   bool     `json:"bada"`
	Errno  int      `json:"errno"`
	Blob   string   `json:"blob"`
	Barray []string `json:"blobarray,omitempty"`
	Nonce  uint32   `json:"nonce"`
	//Blob  []byte `json:"blob"`
	//	Barray [][]byte `json:"blobarray,omitempty"`
}

func (ct *ACCtMessage) validate() error {
	icutl.DebugLog.Printf("CALL [%p] Validate(%d))\n", ct, ct.Type)
	if (len(ct.Nick) > 0) && (len(ct.Server) > 0) && (len(ct.Channel) > 0) {
		switch ct.Type {
		case ctSeal:
			if len(ct.Blob) > 0 {
				return nil
			}
		case ctOpen:
			if len(ct.Blob) > 6 { //&& len(ct.Opt) > 0 {
				return nil
			}
		case ctAdd:
			return nil

		} // end of switch..
	} // end of if...

	icutl.DebugLog.Printf("RET [%p] Validate(%d) -> [Error: Invalid CT message]\n", ct, ct.Type)
	return fmt.Errorf("invalid KX[%d] message", ct.Type)
}

func (ct *ACCtMessage) HandlerCTSEAL() (msgReply []byte, err error) {
	//var acctx *ickp.SecretKey
	//var acBlobArray [][]byte
	var acBlobArray []string
	var out []byte
	var reqBlobTmp []byte

	icutl.DebugLog.Printf("CALL [%p] HandlerCTSEAL([%d/%s/%s] <%s> %08s)\n",
		ct,
		ct.Type,
		ct.Server,
		ct.Channel,
		ct.Nick,
		ct.Blob)

	err = ct.validate()
	if err != nil {
		msgReply, _ = json.Marshal(&ACCtReply{
			Type:  ctSealReply,
			Bada:  false,
			Errno: -1,
			Blob:  err.Error(),
		})
		icutl.DebugLog.Printf("RET [%p] HandlerCTSEAL([%d/%s/%s] <%s> %04s) -> [Error: %s]\n",
			ct,
			ct.Type,
			ct.Server,
			ct.Channel,
			ct.Nick,
			ct.Blob, err.Error())
		return
	}

	acctx, ok_a := ickp.ACmap.GetSKMapEntry(ct.Server, ct.Channel)
	acrnd, ok_b := ickp.ACmap.GetRDMapEntry(ct.Server, ct.Channel)

	if ok_a == false || ok_b == false {
		err = fmt.Errorf("No key/Corrupted key/rnd map")
		msgReply, _ = json.Marshal(&ACCtReply{
			Type:  ctSealReply,
			Bada:  false,
			Errno: -2,
			Blob:  err.Error(),
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
	// let's encrypt to see how big is the message
	// PRIVMSG <chan> :<encrypted msg><\r\n> < 512 bytes
	out, err = iccp.CreateACMessageNACL(acctx, acrnd, []byte(ct.Blob[:]), []byte(ct.Nick))
	ctLen := len(out)           // <ac> AbBDKLFl==
	ctLen += len(ct.Channel)    // #channel
	ctLen += len(IRCMSG_PREFIX) // PRIVMSG ...: (1 byte candy)
	ctLen += len(IRCMSG_SUFFIX) // \r\n (ending)
	ctLen += 1                  // candy! :)

	if msgLen < IRCMSG_MAXSIZE {
		acBlobArray = append(acBlobArray, string(out))
	} else {
		nBlock := msgLen / (IRCMSG_MAXSIZE - (len(ct.Channel) + len(IRCMSG_PREFIX) + len(IRCMSG_SUFFIX) + 1))
		nBlock++

	}

	msgLen := ctLen
	//msgLen := iccp.oldPredictLenNACL([]byte(ct.Blob)) + len(ct.Channel) + 14
	//nBlock := msgLen/410 + 1
	if msgLen < IRCMSG_MAXSIZE {
		acBlobArray = append(acBlobArray, string(out))
	} else {
		// XXX TODO what was working..
		//msgLen := iccp.PredictLenNACL(msgLen) + len(ct.Channel) + 14
		//nBlock := msgLen/(512-(len(ct.Channel)+11+2+1)) + 1
		nBlock := msgLen / (IRCMSG_MAXSIZE - (len(ct.Channel) + len(IRCMSG_PREFIX) + len(IRCMSG_SUFFIX) + 1))
		nBlock++

		// BUG HERE with offsets...
		for j, bSize, bAll, bPtr := 0, len(ct.Blob)/nBlock, len(ct.Blob), 0; j < nBlock; j, bPtr = j+1, bPtr+bSize {
			if bPtr+bSize+1 >= bAll {
				reqBlobTmp = []byte(ct.Blob)[bPtr:]
				//fmt.Fprintf(os.Stderr, "** %d block[%d:%d]: %s \n", j, bPtr, bAll, reqBlobTmp)
				//fmt.Fprintf(os.Stderr, ">> %d => %c || %d => %c\n", bAll, reqBlob[bAll-1], bAll+1, reqBlob[bAll+1])
				//reqBlob[bPtr:bAll]
			} else {
				reqBlobTmp = []byte(ct.Blob)[bPtr : bPtr+bSize]
				//fmt.Fprintf(os.Stderr, ">>#%d block[%d:%d]: %s \n", j, bPtr, bPtr+bSize, reqBlobTmp)
				//reqBlob[bPtr : bPtr+bSize]
			} // END OF ELSE

			//fmt.Fprintf(os.Stderr, ">> NEW #%d block[%d:%d]: %s \n", j, bPtr, bPtr+len(reqBlobTmp), reqBlobTmp)
			out, err = iccp.CreateACMessageNACL(acctx, acrnd, reqBlobTmp, []byte(ct.Nick))
			if err != nil {
				msgReply, _ = json.Marshal(&ACCtReply{
					Type:  ctSealReply,
					Bada:  false,
					Errno: -3,
					Blob:  err.Error(),
				})
				return
			}
			acBlobArray = append(acBlobArray, string(out))
		} // END OF FOR
	}
	msgReply, _ = json.Marshal(&ACCtReply{
		Type:   ctSealReply,
		Bada:   true,
		Errno:  0,
		Nonce:  acctx.GetNonce(),
		Barray: acBlobArray,
	})
	icutl.DebugLog.Printf("RET [%p] HandlerCTSEAL([%d/%s/%s] <%s> %04s) -> [OK::%d:%04s]\n",
		ct,
		ct.Type,
		ct.Server,
		ct.Channel,
		ct.Nick,
		ct.Blob,
		len(acBlobArray),
		acBlobArray)
	icutl.DebugLog.Printf("RET [%p] HandlerCTSEAL msgReply DEBUG: [%s]\n", ct, msgReply)
	return
}

func (ct *ACCtMessage) HandlerCTOPEN() (msgReply []byte, err error) {
	icutl.DebugLog.Printf("CALL [%p] HandlerCTOPEN([%d/%s/%s] <= <%s> %08s)\n",
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
			Type:  ctOpenReply,
			Bada:  false,
			Errno: -1,
			Blob:  err.Error(),
		})
		icutl.DebugLog.Printf("RET [%p] HandlerCTOPEN([%d/%s/%s] <%s> %04s) -> [Error: %s]\n",
			ct,
			ct.Type,
			ct.Server,
			ct.Channel,
			ct.Nick,
			ct.Blob, err.Error())
		return
	}

	//acctx, ok_a := Sk[channel]
	acctx, ok_a := ickp.ACmap.GetSKMapEntry(ct.Server, ct.Channel)
	acrnd, ok_b := ickp.ACmap.GetRDMapEntry(ct.Server, ct.Channel)

	if ok_a == false || ok_b == false {
		err = fmt.Errorf("handlerCTOPEN(): no SKMap/RDMap Entry found")
		msgReply, _ = json.Marshal(&ACCtReply{
			Type:  ctOpenReply,
			Bada:  false,
			Errno: -2,
			Blob:  err.Error(),
		})
		return
	}

	//func OpenACMessage(context * SecKey, cmsg, peerNick []byte) (out []byte, err error) {
	// XXX TODO: use reqOpt accordingly
	out, err := iccp.OpenACMessageNACL(acctx, acrnd, []byte(ct.Blob), []byte(ct.Nick), []byte(ct.Opt))
	if err != nil {
		//err = fmt.Errorf("CTOPEN_Handler(): OpenACMessageNACL() error")
		msgReply, _ = json.Marshal(&ACCtReply{
			Type:  ctOpenReply,
			Bada:  false,
			Errno: -3,
			Blob:  err.Error(),
		})
		return
	}

	msgReply, _ = json.Marshal(&ACCtReply{
		Type:  ctOpenReply,
		Bada:  true,
		Errno: 0,
		Nonce: acctx.GetNonce(),
		Blob:  string(out),
	})

	icutl.DebugLog.Printf("RET [%p] HandlerCTOPEN([%d/%s/%s] <%s> %08s) -> [OK]\n",
		ct,
		ct.Type,
		ct.Server,
		ct.Channel,
		ct.Nick,
		ct.Blob)
	return
}

func (ct *ACCtMessage) HandlerCTADD() (msgReply []byte, err error) {
	icutl.DebugLog.Printf("CALL [%p] HandlerCTADD([%d/%s/%s] <%s> %08s)\n",
		ct,
		ct.Type,
		ct.Server,
		ct.Channel,
		ct.Nick,
		ct.Blob)

	err = ct.validate()
	if err != nil {
		msgReply, _ = json.Marshal(&ACCtReply{
			Type:  ctAddReply,
			Bada:  false,
			Errno: -1,
			Blob:  err.Error(),
		})
		icutl.DebugLog.Printf("RET [%p] HandlerCTADD([%d/%s/%s] <%s> %04s) -> [Error: %s]\n",
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
	skgen := new(ickp.KeyGenerator)
	err = skgen.Init([]byte(ct.Blob), []byte(ct.Channel), []byte(ct.Nick), []byte(ct.Server))
	if err != nil {
		msgReply, _ = json.Marshal(&ACCtReply{
			Type:  ctAddReply,
			Bada:  false,
			Errno: -2,
			Blob:  err.Error(),
		})
		icutl.DebugLog.Printf("RET [%p] HandlerCTADD([%d/%s/%s] <%s> %04s) -> [Error: %s]\n",
			ct,
			ct.Type,
			ct.Server,
			ct.Channel,
			ct.Nick,
			ct.Blob, err.Error())
		return
	}

	// XXX TODO: handle error or remove it...
	acctx, _ := ickp.CreateACContext([]byte(ct.Channel), 0)

	key := make([]byte, 32)
	io.ReadFull(skgen, key)

	newRnd := make([]byte, len(key))
	_, err = rand.Read(newRnd)
	if err != nil {
		msgReply, _ = json.Marshal(&ACCtReply{
			Type:  ctAddReply,
			Bada:  false,
			Errno: -3,
			Blob:  err.Error(),
		})
		icutl.DebugLog.Printf("RET [%p] HandlerCTADD([%d/%s/%s] <%s> %04s) -> [Error: %s]\n",
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

	ickp.ACmap.SetSKMapEntry(ct.Server, ct.Channel, acctx)
	ickp.ACmap.SetRDMapEntry(ct.Server, ct.Channel, newRnd)

	msgReply, _ = json.Marshal(&ACCtReply{
		Type:  ctAddReply,
		Bada:  true,
		Errno: 0,
		Blob:  "OK",
	})
	icutl.DebugLog.Printf("RET [%p] HandlerCTADD([%d/%s/%s] <%s> %04s) -> [OK]\n",
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
	icutl.DebugLog.Printf("CALL HandleCTMsg(msg[%d]:[%s])\n", len(msg), msg)
	req := &ACCtMessage{}

	// let's unmarshall the message first
	err = json.Unmarshal(msg, req)
	if err != nil {
		icutl.DebugLog.Printf("RET HandlerCTMsg(%s) -> [Error: %s]\n", msg, err.Error())
		msgReply, _ = json.Marshal(&ACCtReply{
			Type:  ctErrReply,
			Bada:  false,
			Errno: -1,
			Blob:  err.Error(),
		})
		return
	}

	switch req.Type {
	case ctSeal:
		msgReply, err = req.HandlerCTSEAL()
	case ctOpen:
		msgReply, err = req.HandlerCTOPEN()
	case ctAdd:
		msgReply, err = req.HandlerCTADD()
	default:
		err = fmt.Errorf("invalid CT Message")
		msgReply, _ = json.Marshal(&ACCtReply{
			Type:  ctErrReply,
			Bada:  false,
			Errno: -2,
			Blob:  err.Error(),
		})
	}

	icutl.DebugLog.Printf("RET HandleCTMsg(msg[%d]:[%s]) -> [reply[%d]: %s]\n", len(msg), msg, len(msgReply), msgReply)
	return
}
