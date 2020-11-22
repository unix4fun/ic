
# PROJECT IS NOT MAINTAINED AND OBSOLETED BY A REWRITE
# [WIC](https://git.sr.ht/~eau/wic
# PLEASE USE WIC INSTEAD

# **I**(rc) **C**(rypto) 4 Fun= IC4F

[![Join the chat at https://gitter.im/ic4f/Lobby](https://badges.gitter.im/ic4f/Lobby.svg)](https://gitter.im/ic4f/Lobby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

[![Build Status](https://travis-ci.org/unix4fun/ic.svg?branch=master)](https://travis-ci.org/unix4fun/ic)

## Pitch (it's A WORK IN PROGRESS)

In these time of buzzwords and massive crypto marketing, everybody claim security, inviolability, super crypto guruness, etc.. etc.. 
we don't but we do try to provide a simple solution to our own humble needs, encrypt IRC chat that we use daily in a relatively safe 
and simple fashion.

This is an attempt to provide an (to use and maintain) IRC encryption mechanism with an irc client we like, hopefully better than plaintext and current used/existing ones..  with (hopefully) not too much "false" sense of security.

It is inspired from previous/known/alternative projects that has been done by "pioneers"/"hackers" in underground and take account that IRC have some *limitations*.
(understand don't yell : IT SUCKS! USE OTR! please read and think first)

First project in an inspiring and pragmatic new language : Go

## This Package
* the IC pipe/tool: 'ic'
* client script (weechat)

## Goals

* IRC encryption.
* KISS.
* Reliable.
* Small.
* As safe as I could make it.

I needed something like this *up-to-date* so I tried to do/build it.


## Ideas

So far the design is fairly straight forward, the IRC client itself should/does not have any cryptographic knowledge.

the client script [ic-weechat](https://github.com/unix4fun/ic/client-scripts/weechat/ic-weechat) just *request* services to a little *daemon* running and
communicating on *stdin/stdout/stderr* using JSON serialization.

The IRC script running on the client *request* one of the following:
- generate an ephemeral ECC 25519 assymetric key pair for *my nickname/serv* 
- generate a symmetric key for *chan/serv*
- add the following public key for [nick] 
- list received & stored public key(s)
- encrypt [plaintext] for [chan/serv]
- decrypt [ciphertext] from [chan/serv]
- seal a KEX (Key EXchange / ECDH w/ NaCL) for *nick* (using's *nick*'s public key) on *chan/serv* (exchange the symmetric key for *chan/serv*)
- open a KEX blob from *nick* on *chan/serv* (receive & open the key exchange blob from *nick*, now ready to encrypt on *chan/serv*)

This way the IRC client and its scripts does not store any secret, nor deal with encryption mechanisms, it works *in-memory* only and do NOT store anything on disk.
But you can save all your *channels/serv* keys on disk for re-using later.


## Requirements:

* protobuf-2.6.1+ (if you need to regenerate the go part)
* go-1.5+ (svn, mercurial, git along with go in fact.. / it works compile with go1.2+ but I want to be able to use go generate which is present since 1.4 release, so let's use it...)
* weechat 1.3+

(go get should do the rest of the magic...)

## Building/Installing

Building is done with the `go` tool. If you have setup your GOPATH
correctly, the following should work:

    go get github.com/unix4fun/ic

if any issues occurs, just :

    cd $GOPATH/src/github.com/unix4fun/ic
    go generate
    go build
    go install

or fill up a github issue so we can investigate and fix.

Binary `ic` should then be in `$GOPATH/bin`

    cd $GOPATH/src/github.com/unix4fun/ic && make install

It will copy the following files into :

    ~/.weechat/python/autoload/ic-weechat.py

## Usage


### Let's start

3 main commands:

    /pk
    '/pk' is used to manage Public Keys (ECC key exchange)

    /sk
    '/sk' is used to manage Secret Keys (channel/query keys)

    /ic
    '/ic' is used to enable disable crypto on a specific (weechat) buffer and main script commands

the flow is simple, when you join the channel, you **GENERATE** & **BROADCAST** your public key, so that other channel members are aware of your public key,
other channel members should also **BROADCAST** their own key, a channel member **GENERATE A SECRET** (or already have the) key for the current channel 
to then **EXCHANGE** the (newly created) secret key with other members.


_GENERATE A KeyPair_& _BROADCAST Public Key_|_Public Key Help_
----------|-----------|
/pk gen   | /pk help


_GENERATE Symmetric Key_|_Send K(ey)EX(change)_|_Receive K(ey)EX(change)_|_Secret Key Help_
-------------------|----------|-----------------|----------------
/sk gen {someinput} | /sk give {nickname}|/sk use | /sk help

### I arrive on a new channel, not encrypted

Everything is loaded, you connect irc, and join #prout, #prout is NOT encrypted,
yes you just joined, so type:

    /sk gen <some keyboard garbage input>

you will then notice a red bar appearing above your regular status bar, it means
the current weechat buffer is *ENCRYPTED*.

If you type all messages for #prout will be *ENCRYPTED*, if you do need to speak
in plaintext again, type /ic to toggle encryption of that buffer on and off


### I arrive on a new channel, but it is already encrypted, I cannot read

So you don't have the key, there is not "automatic" requests or such, you need
someone to give you the channel (/shared) key to be able to read the
conversations

So first generate & broadcast an ephemeral key pair (AS A KEY *RECEIVER*): 

    /pk

Now, someone on the channel who has the channel key, has to pass it to you, here is how. 
Generate an ephemeral key pair (AS A KEY *HOLDER*) and broadcast your public key:
    
    /pk

Give the current buffer/channel key (AS A KEY *HOLDER*):

    /sk give <destnickname>



You will see you have received a Key EXchange payload, you can decide to ignore it or to
receive the key for the current buffer (AS A KEY *RECEIVER*):

    /sk use


Now you can chat encrypted with your friends, that's it! :)


Use /pk help, /sk help or /ic help to access the help.

## Featuring (because there is always a star in your production..)

* [NaCL ECC 25519] (http://nacl.cr.yp.to/install.html) box/secretbox [Go implementation](https://godoc.org/code.google.com/p/go.crypto/nacl) with AEAD (using Salsa20 w/ Poly1305 MAC)
* [PBKDF2] (http://en.wikipedia.org/wiki/PBKDF2) for key generation using input entropy (/sk gen|CT_ADD script command)
* [HMAC KDF] (http://en.wikipedia.org/wiki/Key_derivation_function) using SHA-3 (w/ a salt for key based on crypto/rand Go implementation)
* [SHA-3] (http://en.wikipedia.org/wiki/SHA-3) in various area, including NONCE generation (low probability of collision property)
* [Go] (http://golang.org) because I like trying something new and promising.
* [Weechat] (http://weechat.org/) because I like trying something new and promising.

## Known Weaknesses

* no [PFS] (http://en.wikipedia.org/wiki/Perfect_Forward_Secrecy)
* Evil IRC server MITM wins. (will be fixed with identity keys)
* [Go crypto implementation] (https://godoc.org/code.google.com/p/go.crypto): is it safe?
* [EC Curve 25519] (http://cr.yp.to/ecdh.html): is it really safe? 
* memory is swappable to disk and not encrypted (**yet**).

## Ordered TODO:

* unit/regression testing in Go (bleh_test.go).
* add AES-GCM as an alternative AEAD (In addition to NaCL poly1305/salsa20)
* benchmark and code cleanup, huge code cleanup.
* identity RSA/Ed25519 keys (currently in study/dev) with ala SSH authorized_nicks (for trusted KEX/messages).
* document JSON protocol for other IRC client plugin writers
* rename a SKMap key (for queries automagically on nick change)
* rename a PKMap key (on nick change)
* evaluate feasibility of socialist milionnaire probleme implementation (like OTR).
* try to avoid page to disk memory
* scrub memory before deleting the objects
* check/audit/fuzz source code
* daemon protobuf ping heartbeat
* irssi plugin/script.


## Done
* encrypted runtime memory key storage (done but not clean)
* load/save channel/query keys on disk (using AES-GCM 256 in "adapted" PEM format)
* fix IRC truncated encrypted messages (done but not clean)

The daemon is implemented in Go langage and will produce a binary.

## Design/Format

(IRC network) <=> IRC Client <--stdin/stdout--> IC --> [infamous crypto keys]

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



