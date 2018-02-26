// +build go1.4

//go:generate protoc --go_out=iccp -Iiccp iccp/iccp.proto
//make version
//echo "package main\nvar Version string '`date +%Y%m%d`'\n" > version.go

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"

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

	go func() {
		runtime.LockOSThread()
		log.Println(http.ListenAndServe("localhost:6060", nil))
		runtime.UnlockOSThread()
	}()

	// parsing the RSA code...
	rsaFlag := flag.Bool("genrsa", false, "generate RSA identity keys")
	ecFlag := flag.Bool("genec", false, "generate ECDSA identity keys (these are using NIST curve SecP384")
	saecFlag := flag.Bool("gen25519", false, "generate EC 25519 identify keys")
	dbgFlag := flag.Bool("debug", false, "activate debug log")
	//jsonFlag := flag.Bool("json", true, "use json communication channel")

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
		var keyType int
		var err error

		switch {
		case *rsaFlag == true:
			keyType = ickp.KEYRSA
			//i, err = ickp.NewIdentityKey(ickp.KEYRSA)
			//ickp.GenKeysRSA(rand.Reader)
		case *ecFlag == true:
			keyType = ickp.KEYECDSA
			//i, err = ickp.NewIdentityKey(ickp.KEYECDSA)
			//ickp.GenKeysECDSA(rand.Reader)
		case *saecFlag == true:
			keyType = ickp.KEYEC25519
			//ickp.GenKeysED25519(rand.Reader)
		}

		// creating and saving key
		i, err = ickp.NewIdentityKey(keyType)
		if err != nil {
			panic(err)
		}

		icutl.DebugLog.Printf("bleh i: %p err: %v", i, err)
		err = i.ToKeyFiles("/home/rival/.ic/ic_id", []byte("proutprout"))
		if err != nil {
			panic(err)
		}

		// loading the saved key
		i2, err := ickp.LoadIdentityKey("/home/rival/.ic/ic_id", []byte("proutprout"))
		if err != nil {
			panic(err)
		}

		fmt.Printf("SAVED KEY: %v\n", i)
		fmt.Printf("LOADED KEY: %v\n", i2)

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
