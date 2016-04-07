package acjs

import "github.com/unix4fun/ac/acutl"

//
//
// Handle Crypto MESSAGES..
//
//
func HandleCTMsg(msg []byte) (msgReply []byte, err error) {
	acutl.DebugLog.Printf("CALL HandleCTMsg(msg[%d]:[%s])\n", len(msg), msg)
	acutl.DebugLog.Printf("RET HandleCTMsg(msg[%d]:[%s]) -> [reply[%d]: %s]\n", len(msg), msg, len(msgReply), msgReply)
	return
}
