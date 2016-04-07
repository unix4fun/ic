package acjs

import "github.com/unix4fun/ac/acutl"

//
//
// Handle Control MESSAGES..
//
//
func HandleCLMsg(msg []byte) (msgReply []byte, err error) {
	acutl.DebugLog.Printf("CALL HandleCLMsg(msg[%d]:[%s])\n", len(msg), msg)
	acutl.DebugLog.Printf("RET HandleCLMsg(msg[%d]:[%s]) -> [reply[%d]: %s]\n", len(msg), msg, len(msgReply), msgReply)
	return
}
