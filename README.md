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

# Design/Format

Simple schema:
IRC Client <- acprotocol -> AC <--> (infamous crypto)

keys should never appear in clear and should be "randomly" (as far as my crypto user knowledge goes) generated.

# Featuring

* NaCL ECC 25519 box/secretbox with AEAD
* PBKDF2 (key generation)
* HKDF (salt for key based on prng)
* SHA-3
* Go

# Weaknesses
* no PFS
* Evil server wins

# Todo

in no particular order..
* identity RSA keys (currently in study/dev)
* ala SSH authorized_nicks (for trusted KEX/messages)
* irssi plugin/script.
* encrypted runtime memory key storage
* try to avoid page to disk memory
* scrub memory before deleting the objects
* unit/regression testing in Go (bleh_test.go).
* check/audit source code

The daemon is implemented in Go langage and will produce a binary.


# Requirements:

protobuf-2.5.0+ (if you need to regenerate the go part)
go-1.2+
(svn, mercurial, git along with go in fact..)

(go get should do the rest of the magic...)

# Building

Building is done with the `go` tool. If you have setup your GOPATH
correctly, the following should work:

    go get github.com/unix4fun/ac

Binary should then be in $GOPATH/bin

MORE TO COME...
