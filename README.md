Another Crypto daemon

An attempt to provide an IRC encryption mechanism that is not perfect, but
hopefully better than plaintext..

it is inspired from previous/known/alternative projects that has been done by "pioneers" or
e-settlers.
IRC also have some limitations

It's also a first project in an inspiring new language : Go

# Goals

* IRC encryption.
* KISS.
* Reliable.
* Small.
* As safe as I could make it.

I needed something like this up-to-date so I tryied to do it.

# Ideas

So far the design is fairly straight forward, the irc client itself should not
have any crypto knowledge.

the client just "request" services to a little "daemon" running and
communicating on stdin/stdout using Google Protobuf serialization

irc client ask one of the following:
- get my public key
- get [nick] stored public key
- encrypt [plaintext] for [chan/serv]
- decrypt [ciphertext] from [chan/serv]
- build a KEX (Key EXchange) blob for [nick] on [chan/serv]
- open a KEX blob from [nick] on [chan/serv]
- generate a ECC pub/priv key pair for [my nickname/serv] 
- generate a symmetric key pair for [chan/serv]

This way the IRC client does not store any secret, nor deal with encryption
mechanisms, it does not parse messages

# Design/Format

(IRC network) <=> IRC Client <-stdin/stdout-> AC --> [infamous crypto keys]

IRC Message Format:
[<ac>] <blob>         : Encrypted Messages
[<acpk>] <blob>       : Public key Messages
[<ackx:nick> <blob>]  : KEX Messages

Encrypted Messages Format:
TODO

Public Key Messages Format:
TODO

KEX Messages Format: 
TODO

keys should never appear in clear and should be "randomly" (as far as my crypto user knowledge goes) generated.

# Featuring

* NaCL ECC 25519 box/secretbox with AEAD (using Salsa20 w/ Poly1305 MAC)
* PBKDF2 (key generation)
* HKDF (salt for key based on prng)
* SHA-3
* Go

# Weaknesses
* no PFS
* Evil server wins
* ?Go crypto implementation?
* ?EC Curve 25519 is it really safe? 
* ?Go crypto PRNG?

# Todo

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


# Requirements:

* protobuf-2.5.0+ (if you need to regenerate the go part)
* go-1.2+ (svn, mercurial, git along with go in fact..)

(go get should do the rest of the magic...)

# Building

Building is done with the `go` tool. If you have setup your GOPATH
correctly, the following should work:

    go get github.com/unix4fun/ac

Binary should then be in $GOPATH/bin

MORE TO COME...
