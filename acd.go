// ACD: Arsene Crypto Daemon main file
package main

import (
    "fmt"
    "net"
    "os"
    "os/signal" // XXX deactivated
//    "time"
//    "log" // XXX deactivated
    "syscall" // XXX deactivated
//    "arsene/ac/proto"
//    "bytes"
//    "encoding/base64"
//    "encoding/binary"
//    "encoding/hex"
//    "compress/zlib"
//    "crypto/rand"
//    "io"
//    "io/ioutil"
//    "code.google.com/p/go.crypto/nacl/box"
//    "code.google.com/p/go.crypto/sha3"
//    "arsene/ac/ocb"
//    "arsene/ac/obf"
//    "arsene/ac/proto"
    "github.com/unix4fun/ac/acpb"
//    "code.google.com/p/goprotobuf/proto"
)

func Usage(mycmd string) {
    fmt.Fprintf(os.Stderr, "%s [options]", mycmd)
}

func handleClient(conn net.Conn) (err error) {
    var buf []byte

    buf = make([]byte, 4096)

    for {
        // XXX TODO: we need to rewrite this, using Length prefix Framing, such
        // as [ uint16 ] [ Protobuf Message ]
        n, errr := conn.Read(buf[0:])
        if errr != nil {
            return err
        }

        fmt.Printf("SOCKET READ: %d bytes\n", n)
        msgReply, acErr := acpb.HandleACMsg(buf[:n])
        //msgReply, acErr := acpb.HandleACMsg(buf)
        if acErr != nil {
            //fmt.Println(acErr)
            if msgReply != nil {
                conn.Write(msgReply)
            }
            return acErr
        } else {
            conn.Write(msgReply)
            return nil
        }
    }
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
        } else {
            os.Stdout.Write(msgReply)
            return nil
        }
    } /* end of for() */
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
    * XXX deactivated...
    This is the HANDLE CLIENT PART we're rewriting from scratch grlmgrlmbl..
    l, err := net.Listen("unix", "./acd.socket")
    if err != nil {
        log.Fatal("listen error:", err)
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

    /*
    for acpb.ACrun == true {
        conn, err := l.Accept()
        if err != nil {
            continue
        }
        // XXX TODO: need to handle error...
        handleClient(conn)
        conn.Close() // we're finished
    }
    */

    //fmt.Fprintf(os.Stderr, "PROUT PROUT EXITING NOW\n")
    //l.Close() //XXX deactivated
    os.Exit(0)
}
