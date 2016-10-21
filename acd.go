// +build go1.4
//go:generate protoc --go_out=accp -Iaccp accp/accp.proto
//make version
//echo "package main\nvar Version string '`date +%Y%m%d`'\n" > version.go

package main

import (
	"flag"
	"fmt"
	//"github.com/pkg/profile"
	"github.com/unix4fun/ac/acjs"
	"github.com/unix4fun/ac/ackp"
	"github.com/unix4fun/ac/acutl"
	"io/ioutil"
	"os"
	// we are replacing protobuf with basic json, so we can get rid of the
	// protobuf dependency in the client script..
	//"github.com/unix4fun/ac/acpb"
)

//
//        ____ ___     _______  _____
//  __ __/ / // _/    /  _/ _ |/ ___/
// / // /_  _/ _/  ^  / // __ / /_
// \_,_/ /_//_/     /___/_/ |_\___/ (irc advanced crypto)
// Unix4Fun
// Some people doing some stuff somewhere for some reasons...
//
// https://unix4fun.github.io/
//
// This is u4f Irc A. Crypto
//
// A simple way to crypt your conversation(s) if, like us, you remain on IRC.
// #Slack / HipChat / whatever are soooo overrated...
//
//

// ACD will be renamed uIAC -> u4f Irc Annoying Crypto
// iacd -> irc advanced crypto daemon
func usage(mycmd string) {
	fmt.Fprintf(os.Stderr, "%s [options]", mycmd)
}

func init() {
	//fmt.Printf("INIT NINITNI INIT!!\n")
}

func main() {
	Version := acVersion

	//cpuProfile := profile.Start(profile.ProfilePath("."), profile.CPUProfile)

	/*
		f, err := os.Create("ac.pprof")
		if err != nil {
			panic(err)
		}
		g, err := os.Create("ac.mprof")
		if err != nil {
			panic(err)
		}

		err = pprof.StartCPUProfile(f)
		if err != nil {
			panic(err)
		}
	*/
	//defer f.Close()
	//defer pprof.StopCPUProfile()

	// parsing the RSA code...
	rsaFlag := flag.Bool("rsagen", false, "generate RSA identity keys")
	ecFlag := flag.Bool("ecgen", false, "generate ECDSA identity keys (these are using NIST curve SecP384")
	saecFlag := flag.Bool("ec25gen", false, "generate EC 25519 identify keys")
	dbgFlag := flag.Bool("debug", false, "activate debug log")
	//jsonFlag := flag.Bool("json", true, "use json communication channel")
	/*
		cpuProfile := flag.String("cpuprofile", "", "write cpu profile to file")
		memProfile := flag.String("memprofile", "", "write mem profile to file")
	*/
	// we cannot use more than 2048K anyway why bother with a flag then
	//bitOpt := flag.Int("client", 2048, "generate Client SSL Certificate")
	flag.Parse()

	/*
		if len(flag.Args()) != 1 {
			usage(os.Args[0])
			flag.PrintDefaults()
			os.Exit(1)
		}
	*/

	if *dbgFlag == true {
		//log.SetOutput(os.Stderr)
		acutl.InitDebugLog(os.Stderr)
	} else {
		//log.SetOutput(ioutil.Discard)
		acutl.InitDebugLog(ioutil.Discard)
	}

	if *rsaFlag == true || *ecFlag == true || *saecFlag == true {
		// generate a set of identity RSA keys and save them to file encrypted
		//accp.GenRSAKeys()
		var i *ackp.IdentityKey
		var err error

		identity := flag.Arg(0)

		switch {
		case *rsaFlag == true:
			i, err = ackp.NewIdentityKey(ackp.KEYRSA, identity)
			//ackp.GenKeysRSA(rand.Reader)
		case *ecFlag == true:
			fmt.Printf("LET'S SWITCH!!: %v -> %s\n", *ecFlag, identity)
			i, err = ackp.NewIdentityKey(ackp.KEYECDSA, identity)
			//ackp.GenKeysECDSA(rand.Reader)
		case *saecFlag == true:
			i, err = ackp.NewIdentityKey(ackp.KEYEC25519, identity)
			//ackp.GenKeysED25519(rand.Reader)
		}
		acutl.DebugLog.Printf("bleh i: %p err: %p", i, err)
		err = i.ToKeyFiles("/Users/eau/.ac/ac_id", []byte("proutprout"))
		if err != nil {
			panic(err)
		}

	} else {
		// find and load the keys in memory to sign our requests
		// private key will need to be unlocked using PB request
		// may be it should be loaded on-demand
		//ackp.LoadIdentityKeys()

		// load authorized_nicks file
		//ackp.LoadAuthFile()

		// memory storage maps init..
		//ackp.ACmap = make(ackp.PSKMap)
		ackp.ACrun = true

		//fmt.Fprintf(os.Stderr, "[+] ac-%s\nstart\n", Version)
		acutl.DebugLog.Printf("ac-%s", Version)

		// main loop
		for ackp.ACrun == true {
			acjs.HandleStdin()
		}

		acutl.DebugLog.Printf("ac-%s QUITTING NOW!", Version)
		/*
			pprof.WriteHeapProfile(g)
			g.Close()
			pprof.StopCPUProfile()
			f.Close()
		*/
	}
	//cpuProfile.Stop()

	os.Exit(0)
}
