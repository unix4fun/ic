// +build go1.2
// ACD: Arsene Crypto Daemon main file
package main

import (
	"fmt"
	"os"
	"os/signal" // XXX deactivated
	//    "time"
	//    "log" // XXX deactivated
	// XXX temporary..
	//"crypto/rand"
	//"github.com/unix4fun/ac/accp"
	"github.com/unix4fun/ac/acpb"
	"syscall" // XXX deactivated

	//"runtime/pprof"
	//"go/build"
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

	/*
		f, err := os.Create("toto.pprof")
		if err != nil {
			panic(err)
		}

		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	*/

	/*
		ctx, err := accp.CreateACContext([]byte("#prout"), 0xdeadbeef)
		rnd := make([]byte, 32)

		keyzm := make([]byte, 32)
		_, err = rand.Read(keyzm)
		ctx.SetKey(keyzm)

		fmt.Printf("-- NONCE: %08x\n", ctx.GetNonce())

		toto := []byte("ldkaklj l adlkajs dlaksjd laskjd lsakdjal kdjsa ldkhjdsakhjdkjsahdkjsahdkjsa hdhsa kdhsa kjd askj dakjsh dkjsah dkjsa hdkjsa hdkjsa hdkjsa hdkja hkjdas hkjd hsakjd hsakjdjhdakjhd akj hdkjsa hdkjajs kda k4;lk mm m432,m ,m.,m4 32mmmmmmm432 ,m432, m,43m2 ,miui4u3i2o u879879s98fdscncnnnv ,;l;a;lkeq;wl;lk;qk1209002p32p[o4p32opop4o3popopo5p4lklk54lklkl4nmnmdahkjhdakjhakjgnbnmbnamnbnmn,5mn2,m,mn,mn453,mn,mn,m43n,m,mn,mn,m3ndsjhkjhdauyicytzxytuzyc xrtyrzcxrecztrexrectxrzextcrzxecztrxceztrxcetrzcezrtextrcexztrxectxuzyioocofslfdjslkfjsdkjfsldjlkjglfkjfldkjlkdsjfglksjfdlkjlweyeytwqretyqwreqwyureqjk kh kjh kjhkashalkdjas dsajk kdja daksjd akdja dlajd lsakjda lsjdas dalskjda lkdjsa lkdajd lasjdl sajdlkas jlkdajs dlksaj dlksaj lkaj lk3qjlk23j4 l23kj42 lj42 l3kj42 3j4lk23j4 l32j4lk32 jlk32j4 23lkj4 lk32j l 4k23j4 32lk4j2 lkj423 lk4j2 l4lk32j4lk23j l4j32lk4 lk2 j4lk32 j4lj4l32 j4l32 jlk432 jlk4 32jl4 32lk4 j32lkj4lk32 j4l j4lk2 jlk432 jlk4 j32l j432lk j4lk32 j4lk32 a")
		//toto := []byte("pouet pouet pouet")
	*/
	/*
			pouet, err := accp.CompressData(toto)
			if err != nil {
				panic(err)
			}
			prout, err := accp.DecompressData(pouet)
			if err != nil {
				panic(err)
			}

		fmt.Printf("PROUT LEN: %d\n", len(prout))
		fmt.Printf("TOTO LEN: %d\n", len(toto))
	*/

	/*
		fmt.Printf("TOTO PREDICT NACL LEN: %d\n", accp.PredictLenNACL(toto))

		//for t := 0; t < 20; t++ {
		cmsg, err := accp.CreateACMessageNACL(ctx, rnd, toto, []byte("spoty"))
		if err != nil {
			panic(err)
		}
		fmt.Printf("TOTO REAL NACL LEN: %d\n", len(cmsg))

		fmt.Printf("ACMessageNACL: %s\n", cmsg)
		fmt.Printf("-- NONCE: %08x\n", ctx.GetNonce())

		plain, perr := accp.OpenACMessageNACL(ctx, rnd, cmsg, []byte("spoty"), []byte("hiuu"))
		if perr != nil {
			panic(perr)
		}
		fmt.Printf("PLAIN: %s\n", plain)
		fmt.Printf("-- NONCE: %08x\n", ctx.GetNonce())
	*/

	/*
		jeob, err := accp.CreateMyKeys(rand.Reader, string("jeob"), string("user@user.com"), string("freenode"))
		spoty, err := accp.CreateMyKeys(rand.Reader, string("spoty"), string("userizkjdsk@user.com"), string("freenode"))

		//func CreateKXMessageNACL(context *SecKey, rnd []byte, peerPubkey, myPrivkey *[32]byte, channel, myNick, peerNick []byte) (out []byte, err error) {
		kxmsg, err := accp.CreateKXMessageNACL(ctx, rnd, jeob.GetPubkey(), spoty.GetPrivkey(), []byte("#prout"), []byte("spoty"), []byte("jeob"))
		fmt.Printf("KXMessageNACL: %s\n", kxmsg)
		fmt.Printf("-- NONCE: %08x\n", ctx.GetNonce())

		//func OpenKXMessageNACL(peerPubkey, myPrivkey *[32]byte, cmsg, channel, myNick, peerNick []byte) (context *SecKey, SecRnd []byte, err error) {
		_, rnd, err = accp.OpenKXMessageNACL(spoty.GetPubkey(), jeob.GetPrivkey(), kxmsg, []byte("#prout"), []byte("jeob"), []byte("spoty"))
		if err != nil {
			panic(err)
		}
	*/

	/*
		tcmsg, terr := accp.CreateACMessageNACL(ctx, rnd, []byte("proutprout tagada tsoin tsoin"), []byte("spoty"))
		if terr != nil {
			panic(terr)
		}
		fmt.Printf("ACMessage: %s\n", tcmsg)

		plain, perr = accp.OpenACMessageNACL(ctx, rnd, tcmsg, []byte("spoty"), []byte("hiuu"))
		if perr != nil {
			panic(perr)
		}
		fmt.Printf("PLAIN: %s\n", plain)
	*/
	//}

	//os.Exit(1)

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
