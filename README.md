# **A**(nother) **C**(rypto) = AC
# WORK IN PROGRESS

[![Join the chat at https://gitter.im/unix4fun/ac](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/unix4fun/ac?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

An attempt to provide a rather simple (to use and maintain) IRC encryption mechanism, but hopefully better than plaintext and current used ones..
with (hopefully) no "false" sense of security.

It is inspired from previous/known/alternative projects that has been done by "pioneers" or e-settlers.. as well as in underground and take account that IRC have some *limitations*.

It's my first project in an inspiring and pragmatic new language : Go

## This Package
* the AC pipe binary: 'ac'
* client scripts (weechat)

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

(IRC network) <=> IRC Client <--stdin/stdout--> AC --> [infamous crypto keys]

### IRC Message Format:
```
<ac> [base64_blob]         : Encrypted Messages
<acpk> [base64_blob]       : Public key Messages
<ackx:nick> [base64_blob]  : KEX Messages
```


### Channel/Query Key Generation:
```
<CHANNEL_KEY> is built the following way:
 HKDF_SHA3-256(
         secret:<PBKDF_SHA3-256_GENERATOR>, 
         salt:<CRYPTO_RAND_256>, 
         info:<SHA3_INFO>
 )

where <PBKDF_SHA3-256_GENERATOR> is :
 PBKDF2_SHA3-256(
         pass:<USER_INPUT>, 
         salt:<CRYPTO_RAND_256>, 
         iteration:4096,
         len:32
 )

and <SHA3_INFO> is:
 SHA3(<server_name>||':'||<nickname>||':'||<channel_name>)

```

### Encrypted Messages Format:
```
Base64(
        'ACheader' ||
        <NonceInt32Value> ||
        NACL_SEAL(
            plain: Zlib(<Plaintext>)
            nonce: <NONCE_AUTH>,
            key: <CHANNEL_KEY>,
        ) 
)

where <NonceInt32Value> is:
 a non repeating 32bit counter starting at 0, for each new channel key.

where <NONCE_AUTH> is:
 SHA3( SHA3('CHANNEL') || 
       ':' || 
       SHA3('SRC_NICK') || 
       ':' || 
       SHA3('NONCE_VALUE') || 
       ':' || 
       SHA3('ACheader')
 )

```


### Public Key Messages Format:
```
Base64(
        'PKheader' ||
        Zlib(<NACL_PUBKEY>)
)
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
* identity RSA keys (currently in study/dev) with ala SSH authorized_nicks (for trusted KEX/messages)
* evaluate feasibility of socialist milionnaire probleme implementation (like OTR).
* rename a SKMap key (for queries automagically on nick change)
* rename a PKMap key (on nick change)
* irssi plugin/script.
* xchat plugin/script.
* try to avoid page to disk memory
* scrub memory before deleting the objects
* unit/regression testing in Go (bleh_test.go).
* huge code cleanup
* check/audit source code
* load/save channel/query keys on disk
* daemon protobuf ping heartbeat
* fix IRC truncated encrypted messages

## Done
* encrypted runtime memory key storage (to some extent..)

The daemon is implemented in Go langage and will produce a binary.


## Requirements:

* protobuf-2.4.1+ (if you need to regenerate the go part)
* go-1.4+ (svn, mercurial, git along with go in fact.. / it works compile with go1.2+ but I want to be able to use go generate which is present since 1.4 release, so let's use it...)

(go get should do the rest of the magic...)

## Building/Installing

Building is done with the `go` tool. If you have setup your GOPATH
correctly, the following should work:

    go get github.com/unix4fun/ac

if any issues occurs, just :

    cd $GOPATH/src/github.com/unix4fun/ac
    go generate
    go build
    go install

Binary `ac` should then be in `$GOPATH/bin`

    cd $GOPATH/src/github.com/unix4fun/ac && make install

It will copy the following files into :

    ~/.weechat/python/ac_pb2.py
    ~/.weechat/python/autoload/ac-weechat.py

## Usage

3 main commands:

    /pk
    '/pk' is used to manage Public Keys (ECC key exchange)

    /sk
    '/sk' is used to manage Secret Keys (channel/query keys)

    /ac
    '/ac' is used to enable disable crypto on a specific (weechat) buffer

the flow is simple, when you join the channel, you **GENERATE** and then **BROADCAST** you public key, so that other channel members are aware of your public key,
other channel members should also **BROADCAST** their own key, someone on the channel **GENERATE A SECRET**  Key for the current channel and then **EXCHANGE** the newly created secret key with other members.


_GENERATE Public Key_|_BROADCAST Public Key_|_GENERATE Symmetric Key_|_EXCHANGE_|_Public Key Help_|_Secret Key Help_
----------|-----------|-------------------|----------|-----------------|----------------
/pk gen   | /pk       | /sk gen <someinput> | /sk give <nickname>|/pk help | /sk help



Use /pk help, /sk help or /achelp to access the help.
