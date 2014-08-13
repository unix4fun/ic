A(simple) Crypto Daemon

An attempt to provide an IRC encryption mechanism that is not perfect, but
hopefully better than plaintext..

it is inspired from previous projects that has been done by "pioneers" or
e-settlers.

It's also a first project in an inspiring new language : Go

I needed something like this up-to-date so I tryied to do it.

So far the design is fairly straight forward, the irc client itself should not
have any crypto knowledge.

the client just "request" services to a little "daemon" running and
communicating on stdin/stdout using Google Protobuf serialization

Simple schema:
IRC Client <- acprotocol -> AC <--> (infamous crypto)

keys should never appear in clear and should be "randomly" generated.

we're using the following:


- NaCL ECC 25519 Curve box/secretbox with AEAD
- PBKDF2 (key geenration)
- HKDF (salt for key based on prng)
- SHA-3

The daemon is implemented in Go langage and will produce a binary.

This is in DEV and instructions to build/install are on the way... gimme time :)

more detailled description to come.


