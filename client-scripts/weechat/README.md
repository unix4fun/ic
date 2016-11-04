# WORK IN PROGRESS
# **I**(rc) **C**(rypto) 4 Fun= IC4F weechat script

## Goals

* IRC encryption.
* KISS.
* Reliable.
* Small.
* As safe as I could make it.

I needed something like this *up-to-date* so I tried to do/build it.

## Requirements:

* python 2.7+
* weechat 0.4.2+ (with python support)
* [IC](https://github.com/unix4fun/ic)

## Building/Installing

Binary `ic` should  be in `$GOPATH/bin`
Edit `ic-weechat.py` to setup `AC_BINARY` to where `ic` binary lies (by default it takes  `$GOPATH/bin`)

git clone this repository in a directory and `cp \*.py` in  `$HOME/.weechat/python` directory then connect weechat and :

    /script load $PATH/ic-weechat.py

for autoload, just `cd $HOME/.weechat/python/` and `ln -s ic-weechat.py autoload/`

you should see something like this in your client when it loads, the script is now ready to run :

    00:30:11       IC | $#%$#@%#%@#$%@#$%@$#%@#$%@#$%@#$%@#$%#@$%#@$%@#$%@#%@#$%@ │
    00:30:11       IC | IRC Crypto 4 Fun 20161102 (c) 2013-2016 unix4fun │
    00:30:11       IC | by eau <eau+ic4f@unix4fun.net> │
    00:30:11       IC | Implements AEAD: NaCL/ECC Curve 25519 w/ Salsa20/Poly1305 (more later) │
    00:30:11       IC | type: /ic help to get HELP!  │
    00:30:11       IC | $#%$#@%#%@#$%@#$%@$#%@#$%@#$%@#$%@#$%#@$%#@$%@#$%@#%@#$%@ │

you're ready to go ;)


## Usage

    /ic help
    /pk help
    /sk help

