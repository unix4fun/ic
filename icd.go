// +build go1.4

//go:generate protoc --go_out=iccp -Iiccp iccp/iccp.proto
//make version
//echo "package main\nvar Version string '`date +%Y%m%d`'\n" > version.go

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/unix4fun/ic/icjs"
	"github.com/unix4fun/ic/ickp"
	"github.com/unix4fun/ic/icutl"
)

//
//        ____ ___     _______  _____
//  __ __/ / // _/    /  _/ _ |/ ___/
// / // /_  _/ _/  ^  / // __ / /_
// \_,_/ /_//_/     /___/_/ |_\___/ (irc crypto 4 fun)
// Unix4Fun
// Some people doing some stuff somewhere for some reasons...
//
// https://unix4fun.github.io/
//
// This is u4f Irc Crypto 4 Fun
//
// A simple way to crypt your conversation(s) if, like us, you remain on IRC.
// #Slack / HipChat / whatever are soooo overrated...
//
//

// ic -> irc crypto daemon
func usage(mycmd string) {
	fmt.Fprintf(os.Stderr, "%s [options]", mycmd)
}

func init() {
	//fmt.Printf("INIT NINITNI INIT!!\n")
}

func main() {
	Version := icVersion

	//cpuProfile := profile.Start(profile.ProfilePath("."), profile.CPUProfile)

	/*
		f, err := os.Create("ic.pprof")
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

	if *dbgFlag == true {
		//log.SetOutput(os.Stderr)
		icutl.InitDebugLog(os.Stderr)
	} else {
		//log.SetOutput(ioutil.Discard)
		icutl.InitDebugLog(ioutil.Discard)
	}

	if *rsaFlag == true || *ecFlag == true || *saecFlag == true {
		// generate a set of identity RSA keys and save them to file encrypted
		//accp.GenRSAKeys()
		var i *ickp.IdentityKey
		var err error

		identity := flag.Arg(0)

		switch {
		case *rsaFlag == true:
			i, err = ickp.NewIdentityKey(ickp.KEYRSA, identity)
			//ickp.GenKeysRSA(rand.Reader)
		case *ecFlag == true:
			fmt.Printf("LET'S SWITCH!!: %v -> %s\n", *ecFlag, identity)
			i, err = ickp.NewIdentityKey(ickp.KEYECDSA, identity)
			//ickp.GenKeysECDSA(rand.Reader)
		case *saecFlag == true:
			i, err = ickp.NewIdentityKey(ickp.KEYEC25519, identity)
			//ickp.GenKeysED25519(rand.Reader)
		}
		icutl.DebugLog.Printf("bleh i: %p err: %v", i, err)
		err = i.ToKeyFiles("/Users/eau/.ic/ic_id", []byte("proutprout"))
		if err != nil {
			panic(err)
		}

	} else {
		// find and load the keys in memory to sign our requests
		// private key will need to be unlocked using PB request
		// may be it should be loaded on-demand
		//ickp.LoadIdentityKeys()

		// load authorized_nicks file
		//ickp.LoadAuthFile()

		// memory storage maps init..
		//ickp.ACmap = make(ickp.PSKMap)
		ickp.ACrun = true

		//fmt.Fprintf(os.Stderr, "[+] ac-%s\nstart\n", Version)
		icutl.DebugLog.Printf("ic4f Irc Crypto 4 Fun version %s", Version)

		// main loop
		for ickp.ACrun == true {
			// TODO handle error
			err := icjs.HandleStdin()
			if err != nil {
				icutl.DebugLog.Printf("ic4f communication error: %v\n", err)
			}
		}

		icutl.DebugLog.Printf("ic4f version %s QUITTING NOW!", Version)
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
