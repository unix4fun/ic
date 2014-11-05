// ACD: Arsene Crypto Daemon main file
package main

import (
	"fmt"
	//"net"
	"os"
	"os/signal" // XXX deactivated
	//    "time"
	//    "log" // XXX deactivated
	"github.com/unix4fun/ac/acpb"
	"syscall" // XXX deactivated
)

func usage(mycmd string) {
	fmt.Fprintf(os.Stderr, "%s [options]", mycmd)
}

func handleStdin() (err error) {
	buf := make([]byte, 4096)
	for {
		n, err := os.Stdin.Read(buf[0:])
		if err != nil {
			return err
		}

		//fmt.Fprintf(os.Stderr, "STDIN READ: %d bytes\n", n)
		msgReply, acErr := acpb.HandleACMsg(buf[:n])
		if acErr != nil {
			//fmt.Println(acErr)
			if msgReply != nil {
				os.Stdout.Write(msgReply)
			}
			return acErr
		}

		os.Stdout.Write(msgReply)
		return nil
	} /* end of for() */
	// XXX need to return Error.New() really...
	return nil
}

func main() {
	fmt.Fprintf(os.Stderr, "[+] acd daemon start\n")

	/*
	   if len(os.Args) != 1 {
	       Usage(os.Args[0])
	       os.Exit(1)
	   }
	*/

	// memory storage maps init..
	acpb.ACmap = make(acpb.PSKMap)
	acpb.ACrun = true

	// XXX TODO: this is not stable enough but should do the trick for now..
	// it is not clear what happens if the ACrun = false is done first
	// but i close the socket on both sides.. and it should clean the
	// socket file running... let's test with the script now :)
	// XXX deactivated
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, os.Interrupt, os.Kill, syscall.SIGTERM, syscall.SIGKILL, syscall.SIGQUIT, syscall.SIGSEGV, syscall.SIGINT)
	//    signal.Notify(sig, nil)
	go func() {
		<-sig
		acpb.ACrun = false
		fmt.Fprintf(os.Stderr, "[+] exiting...!\n")
		os.Exit(3)
	}()

	for acpb.ACrun == true {
		handleStdin()
	}

	os.Exit(0)
}
