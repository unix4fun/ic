# WORK IN PROGRESS
# **A**(nother) **C**(rypto daemon) Weechat Script

## Goals

* IRC encryption.
* KISS.
* Reliable.
* Small.
* As safe as I could make it.

I needed something like this *up-to-date* so I tried to do/build it.

## Requirements:

* protobuf-2.5.0+ (if you need to regenerate the python protobuf include part)
* python 2.7+
* weechat 0.4.2+ (with python support)
* [AC](https://github.com/unix4fun/ac)

## Building/Installing

Binary `ac` should  be in `$GOPATH/bin`
Edit `ac-weechat.py` to setup `AC_BINARY` to where `ac` binary lies (by default it takes  `$GOPATH/bin`)

git clone this repository in a directory and `cp \*.py` in  `$HOME/.weechat/python` directory then connect weechat and :

    /script load $PATH/ac-weechat.py

for autoload, just `cd $HOME/.weechat/python/` and `ln -s ac-weechat.py autoload/`

you should see something like this in your client when it loads, the script is now ready to run :

    15:44:03 AC | $#%$#@%#%@#$%@#$%@$#%@#$%@#$%@#$%@#$%#@$%#@$%@#$%@#%@#$%@
    15:44:03 AC | Alternate Crypto Shuriken 0.4-dev (c) 2013-2014 Security Gigolos
    15:44:03 AC | by eau <eau-code@unix4fun.net>
    15:44:03 AC | Implements AEAD: NaCL/ECC Curve 25519 w/ Salsa20/Poly1305 (more later)
    15:44:03 AC | $#%$#@%#%@#$%@#$%@$#%@#$%@#$%@#$%@#$%#@$%#@$%@#$%@#%@#$%@

you're ready to go ;)


## Usage

    /achelp

