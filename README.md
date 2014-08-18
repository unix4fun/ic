# WORK IN PROGRESS
# **A**(nother) **C**(rypto daemon)

An attempt to provide a rather simple (to use and maintain) IRC encryption mechanism, but hopefully better than plaintext and current used ones..
with (hopefully) no "false" sense of security.

It is inspired from previous/known/alternative projects that has been done by "pioneers" or e-settlers.. as well as in underground and take account that IRC have some *limitations*.

It's my first project in an inspiring and pragmatic new language : Go

## Goals

* IRC encryption.
* KISS.
* Reliable.
* Small.
* As safe as I could make it.

I needed something like this *up-to-date* so I tried to do/build it.



## Ideas

So far the design is fairly straight forward, the IRC client itself should/does not have any cryptographic knowledge.

the client script [ac-weechat](https://github.com/unix4fun/ac-weechat) just *request* services to a little *daemon* running and
communicating on *stdin/stdout/stderr* using [Google Protobuf](https://code.google.com/p/protobuf/) serialization.

IRC script running on the client *request* one of the following:
- get my public key
- get [nick] stored public key(s)
- encrypt [plaintext] for [chan/serv]
- decrypt [ciphertext] from [chan/serv]
- seal a KEX (Key EXchange) blob for *nick* (using's *nick*'s public key) on *chan/serv* (exchange the symmetric key for *chan/serv*)
- open a KEX blob from *nick* on *chan/serv* (receive & open the key exchange blob from *nick*)
- generate a ECC 25519 pub/priv key pair for *my nickname/serv* 
- generate a symmetric key pair for *chan/serv*

This way the IRC client does not store any secret, nor deal with encryption mechanisms, it work *in-memory* only and do NOT store anything on disk.
However we are not yet making sure the page are not swapped to disk. 




## Design/Format

(IRC network) <=> IRC Client <-stdin/stdout-> AC --> [infamous crypto keys]

### IRC Message Format:
```
<ac> base64_blob         : Encrypted Messages
<acpk> base64_blob       : Public key Messages
<ackx:nick> base64_blob  : KEX Messages
```

### Encrypted Messages Format:
```
TODO
```

### Public Key Messages Format:
```
TODO
```

### KEX Messages Format: 
```
TODO
```

keys should never appear in clear and should be "randomly" (as far as my crypto user knowledge goes) generated.

## Featuring (because there is always a star in your production..)

* [NaCL ECC 25519] (http://nacl.cr.yp.to/install.html) box/secretbox [Go implementation](https://godoc.org/code.google.com/p/go.crypto/nacl) with AEAD (using Salsa20 w/ Poly1305 MAC)
* [PBKDF2] (http://en.wikipedia.org/wiki/PBKDF2) for key generation using input entropy (/sk gen|CT_ADD script command)
* [HMAC KDF] (http://en.wikipedia.org/wiki/Key_derivation_function) using SHA-3 (w/ a salt for key based on crypto/rand Go implementation)
* [SHA-3] (http://en.wikipedia.org/wiki/SHA-3) in various area, including NONCE generation (low probability of collision property)
* [Go] (http://golang.org) because I like trying something new and promising.
* [Weechat] (http://weechat.org/) because I like trying something new and promising.

## Known Weaknesses

* no [PFS] (http://en.wikipedia.org/wiki/Perfect_Forward_Secrecy)
* Evil IRC server MITM wins.
* [Go crypto implementation] (https://godoc.org/code.google.com/p/go.crypto): is it safe?
* [EC Curve 25519] (http://cr.yp.to/ecdh.html): is it really safe? 
* memory is swappable to disk and not encrypted (**yet**).

## Todo

in no particular order..
* identity RSA keys (currently in study/dev)
* ala SSH authorized_nicks (for trusted KEX/messages)
* OR socialist milionnaire probleme implementation (like OTR).
* irssi plugin/script.
* encrypted runtime memory key storage
* try to avoid page to disk memory
* scrub memory before deleting the objects
* unit/regression testing in Go (bleh_test.go).
* check/audit source code

The daemon is implemented in Go langage and will produce a binary.


## Requirements:

* protobuf-2.5.0+ (if you need to regenerate the go part)
* go-1.2+ (svn, mercurial, git along with go in fact..)

(go get should do the rest of the magic...)

## Building/Installing

Building is done with the `go` tool. If you have setup your GOPATH
correctly, the following should work:

    go get github.com/unix4fun/ac

Binary `ac` should then be in `$GOPATH/bin`


