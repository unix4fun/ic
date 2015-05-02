// +build go1.4
//go:generate protoc --go_out=accp -Iaccp accp/accp.proto
//go:generate protoc --go_out=acpb -Iacpb acpb/ac.proto
//go:generate protoc --python_out=client-scripts/weechat/ -Iacpb acpb/ac.proto
//make version
//echo "package main\nvar Version string '`date +%Y%m%d`'\n" > version.go
// ACD: Arsene Crypto Daemon main file
package main

import (
	"flag"
	"fmt"
	"github.com/unix4fun/ac/ackp"
	"github.com/unix4fun/ac/acpb"
	"os"
	"os/signal" // XXX deactivated
	"syscall"   // XXX deactivated

	//"runtime/pprof"
	"github.com/unix4fun/ac/acutl"
	"io/ioutil"
	//"runtime"
	//"log"
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
	Version := acVersion
	/*
		f, err := os.Create("toto.pprof")
		if err != nil {
			panic(err)
		}

		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	*/

	// parsing the RSA code...
	rsaFlag := flag.Bool("rsagen", false, "generate RSA identity keys")
	ecFlag := flag.Bool("ecgen", false, "generate ECDSA identity keys (these are using NIST curve SecP384")
	dbgFlag := flag.Bool("debug", false, "activate debug log")
	// we cannot use more than 2048K anyway why bother with a flag then
	//bitOpt := flag.Int("client", 2048, "generate Client SSL Certificate")
	flag.Parse()

	/*
		fmt.Printf("rsaFlag: %v\n", *rsaFlag)
		fmt.Printf("argc: %d\n", len(flag.Args()))
	*/

	if len(flag.Args()) != 0 {
		usage(os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *rsaFlag == true || *ecFlag == true {
		// generate a set of identity RSA keys and save them to file encrypted
		//accp.GenRSAKeys()
	} else {
		// find and load the keys in memory to sign our requests
		// private key will need to be unlocked using PB request
		//accp.LoadRSAKeys()
		// memory storage maps init..
		//ackp.ACmap = make(ackp.PSKMap)
		ackp.ACrun = true

		if *dbgFlag == true {
			//log.SetOutput(os.Stderr)
			acutl.LogInit(os.Stderr)
		} else {
			//log.SetOutput(ioutil.Discard)
			acutl.LogInit(ioutil.Discard)
		}

		//fmt.Fprintf(os.Stderr, "[+] ac-%s\nstart\n", Version)
		acutl.DebugLog.Printf("ac-%s", Version)
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
			ackp.ACrun = false
			//fmt.Fprintf(os.Stderr, "[+] exiting...!\n")
			acutl.DebugLog.Fatalf("exiting.\n")
			//os.Exit(3)
		}()

		for ackp.ACrun == true {
			handleStdin()
		}
	}
	os.Exit(0)
}
