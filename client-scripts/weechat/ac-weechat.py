#
#
# who cares who did this fucking code, read it, debug it, fix it
# you can send an email can you?
#
# feedback and constructive comments:
# eau <eau-code@unix4fun.net>
# 
#

SCRIPT_NAME    = 'ac-weechat'
SCRIPT_AUTHOR  = 'eau <eau-code@unix4fun.net>'
SCRIPT_VERSION = '20150527'
SCRIPT_LICENSE = 'BSD'
SCRIPT_DESC    = 'AC script'

SCRIPT_COMMAND = 'ac'
SCRIPT_BUFFER  = 'ac'

import_ok = True

try:
    import weechat
except ImportError:
    print('This script must be run under WeeChat.')
    print('Get WeeChat now at: http://www.weechat.org/')
    import_ok = False

try:
    import sys, os, string, ast, datetime, select, socket, re, base64, cgi, time, datetime, binascii, hashlib, subprocess, fcntl, time, random, ac_pb2
except ImportError as message:
    print('Missing package(s) for %s: %s' % (SCRIPT_NAME, message))
    import_ok = False


#AC_BINARY = "/Users/eau/dev/git/ac/ac"
#AC_BINARY = "~/dev/go/bin/ac"
# we need to test if the binary is here and fail to load if it is NOT
AC_BINARY = os.environ["GOPATH"]+"/bin/ac"
AC_DEBUGFILE = "./ac.debug.txt"



# it will be  just channel as key, may be chan/server key later or the hash of both...
#acCipherReady = {} # sha1 hash 'channel:server'
#acCipherBar = {} # sha1 hash 'channel:server' store the bar display pointer.
#acRecvKeyBlobs = {} # sha1 hash 'channel:server'
acCipherPrefix = "<ac>"
acKexPrefix = "<ackx:"
acProcess = None
# XXX TODO
acChannelRE = r'^(((![A-Z0-9]{5})|([#+&][^\x00\x07\r\n ,:]+))(:[^\x00\x07\r\n ,:]+)?)$'
acNicknameRE = r'^([a-zA-Z\[\]\\\`\_\^\{\|\}]{1}[[a-zA-Z0-9\[\]\\\`\_\^\{\|\}\-]{0,15})$'
acKexRE = r'^<ackx:([a-zA-Z\[\]\\\`\_\^\{\|\}]{1}[[a-zA-Z0-9\[\]\\\`\_\^\{\|\}\-]{0,15})> (.*)$'
acB64RE = r'([a-zA-Z0-9\\\+]+[=]{0,2})+$'
acKeyPrefix = "<acpk>"

# socket recv buffer size, lets keep simple for now, use BIG only on public key list requests..
#BUF_SMALL = 2048
#BUF_LARGE = 65536

SCRIPT_HDR = 'AC\t'
SCRIPT_COLOR = weechat.color("yellow,blue")

#
#
#
#
#
#
# UTILS/MISC functions
#
#
#
#
#

# return True is b64, False otherwise
def ac_isb64(teststr):
    try:
        if len(teststr) % 4 == 0:
            base64.b64decode(teststr)
        else:
            return False
    except:
        return False
    return True
#
#
#
# PRINT FUNCTIONS..
#
#
#
def ac_print_buflocalinfo(buffer, info):
    return


# this is for the information regarding the buffer we're asking...
BUF_INFO_NICK = 'nick'
BUF_INFO_CHAN = 'chan'
BUF_INFO_SERV = 'serv'
BUF_INFO_TYPE = 'type'
BUF_INFO_PLUG = 'plug'

BI_NICK = BUF_INFO_NICK
BI_CHAN = BUF_INFO_CHAN
BI_SERV = BUF_INFO_SERV
BI_TYPE = BUF_INFO_TYPE
BI_PLUG = BUF_INFO_PLUG

# XXX TODO: need more sanity checks...
def ac_get_buflocalinfo(buffer):
    t = {}
    t[BUF_INFO_NICK] = weechat.buffer_get_string(buffer,"localvar_nick")
    t[BUF_INFO_CHAN] = weechat.buffer_get_string(buffer,"localvar_channel")
    t[BUF_INFO_SERV] = weechat.buffer_get_string(buffer,"localvar_server")
    t[BUF_INFO_TYPE] = weechat.buffer_get_string(buffer,"localvar_type")
    t[BUF_INFO_PLUG] = weechat.buffer_get_string(buffer,"plugin")
    return t


#
# return the userhost for specific server, channel, nick..
# XXX TODO: None or "unavailable" otherwise...
#
def ac_get_userinfo(buffer, nick, channel, server):
# XXX TODO: my nick and all other infos are probably useless... 
#    my_nick = weechat.buffer_get_string(buffer,"localvar_nick")
#    retVal[gtype = weechat.buffer_get_string(buffer,"localvar_type")
#    channel = weechat.buffer_get_string(buffer,"localvar_channel")
#    server = weechat.buffer_get_string(buffer,"localvar_server")
#    plugin = weechat.buffer_get_string(buffer,"plugin")
    
    userhost = "<unknown>"
    infolist = weechat.infolist_get('irc_nick', '', '%s,%s,%s' %(server, channel, nick))
#    if infolist:
#        try:
#            while weechat.infolist_next(infolist):
#                name = weechat.infolist_string(infolist, 'name')
#                if nick == name:
#                    userhost = weechat.infolist_string(infolist, 'host')
#        finally:
#            weechat.infolist_free(infolist)
#
#    infolist = weechat.infolist_get('irc_nick', '', '%s,%s,%s' %(inf[BI_SERV], inf[BI_CHAN], inf[BI_NICK]))
    if infolist:
#        print "INFOLIST DE PUTES"
        try:
            weechat.infolist_next(infolist)
            fields = weechat.infolist_fields(infolist)
            userhost = weechat.infolist_string(infolist, 'host')

#            while weechat.infolist_next(infolist):
#            weechat.infolist_next(infolist)
#            fields = weechat.infolist_fields(infolist)
#            print fields
#            name = weechat.infolist_string(infolist, 'name')
#            weechat.prnt(dabuffer, "%sAC\t name: %s" % ( weechat.color("yellow,blue"), name))
#            if inf[BI_NICK] == name:
#            userhost = weechat.infolist_string(infolist, 'host')
        finally:
            weechat.infolist_free(infolist)
#    weechat.prnt(buffer, "%sAC\tnick: %s" % ( SCRIPT_COLOR, nick))
##    weechat.prnt(buffer, "%sAC\tchannel: %s" % ( SCRIPT_COLOR, channel))
##    weechat.prnt(buffer, "%sAC\tserver: %s" % ( SCRIPT_COLOR, server))
#    weechat.prnt(buffer, "%sAC\tuserhost: %s" % ( SCRIPT_COLOR, userhost))
##    weechat.prnt(buffer, "%sAC\tplugin: %s" % ( SCRIPT_COLOR, plugin))
##    weechat.prnt(buffer, "%sAC\ttype: %s" % ( SCRIPT_COLOR, gtype))

    return userhost
#
#
# FROM IRC RFC:
#
# target     =  nickname / server
#  msgtarget  =  msgto *( "," msgto )
#  msgto      =  channel / ( user [ "%" host ] "@" servername )
#  msgto      =/ ( user "%" host ) / targetmask
#  msgto      =/ nickname / ( nickname "!" user "@" host )
#  channel    =  ( "#" / "+" / ( "!" channelid ) / "&" ) chanstring
#                [ ":" chanstring ]
#  servername =  hostname
#  host       =  hostname / hostaddr
#  hostname   =  shortname *( "." shortname )
#  shortname  =  ( letter / digit ) *( letter / digit / "-" )
#                *( letter / digit )
#                  ; as specified in RFC 1123 [HNAME]
#  hostaddr   =  ip4addr / ip6addr
#  ip4addr    =  1*3digit "." 1*3digit "." 1*3digit "." 1*3digit
#  ip6addr    =  1*hexdigit 7( ":" 1*hexdigit )
#  ip6addr    =/ "0:0:0:0:0:" ( "0" / "FFFF" ) ":" ip4addr
# XXX freenode 15 times not 8 the second part of nicknames
#  nickname   =  ( letter / special ) *8( letter / digit / special / "-" )
#  targetmask =  ( "$" / "#" ) mask
#                  ; see details on allowed masks in section 3.3.1
#  chanstring =  %x01-07 / %x08-09 / %x0B-0C / %x0E-1F / %x21-2B
#  chanstring =/ %x2D-39 / %x3B-FF
#                  ; any octet except NUL, BELL, CR, LF, " ", "," and ":"
#  channelid  = 5( %x41-5A / digit )   ; 5( A-Z / 0-9 )

#
# 
#
#
#  user       =  1*( %x01-09 / %x0B-0C / %x0E-1F / %x21-3F / %x41-FF )
#                  ; any octet except NUL, CR, LF, " " and "@"
#  key        =  1*23( %x01-05 / %x07-08 / %x0C / %x0E-1F / %x21-7F )
#                  ; any 7-bit US_ASCII character,
#                  ; except NUL, CR, LF, FF, h/v TABs, and " "
#  letter     =  %x41-5A / %x61-7A       ; A-Z / a-z
#  digit      =  %x30-39                 ; 0-9
#  hexdigit   =  digit / "A" / "B" / "C" / "D" / "E" / "F"
#  special    =  %x5B-60 / %x7B-7D
#                   ; "[", "]", "\", "`", "_", "^", "{", "|", "}"
#
#

#
#
# PRINTMSG MODIFIER/MSG PARSING FUNCs
#
#

# this is what we get... for CHANNEL
#: stdout/stderr: string: croute | <acpk> qDtHEHjaOnn41qNtJqKuq1r7l0W9PyWk+fvP5Y3i5olWqhdc9sc62gMCAAD//yrCEHg=
#: stdout/stderr: data: proutprout
#: stdout/stderr: modifier: weechat_print
#: stdout/stderr: modifier_data: irc;freenode.#crutcruton;irc_privmsg,notify_message,prefix_nick_default,nick_croute,log1
#
# this is what we get... for PRIVATE
#: stdout/stderr: string: croute | <acpk> prout
#: stdout/stderr: data: proutprout
#: stdout/stderr: modifier: weechat_print
#: stdout/stderr: modifier_data: irc;freenode.croute;irc_privmsg,notify_private,prefix_nick_default,nick_croute,log1
#
# return:
#  [ True/False , display ]
#
#def acParsePrintMessage(raw_tags, msg):
#    return None

def acMessageParsePrintmsg(raw_tags, print_msg):
#    ret_bool = False
#    print raw_tags
#    print print_msg
    plug, name, tags = raw_tags.split(';')
    taglist = tags.split(',')
    ret_nick = ""
    ret_buffer = None
    try:
        taglist.index("irc_privmsg")
        is_privmsg = True
    except ValueError:
        is_privmsg = False
        return [ False, print_msg ]

    if plug == "irc" and is_privmsg:
#        ret_bool = True
        buffer = weechat.buffer_search(plug, name)
        inf = ac_get_buflocalinfo(buffer)

        # my nick..
#        my_nick = inf[BI_NICK]
#        server = inf[BI_SERV]
#        channel = inf[BI_CHAN]
        
        # sanity checks...
        if inf.has_key(BI_CHAN) and inf.has_key(BI_SERV) and inf.has_key(BI_NICK) and acwee.isAcEnabled(inf[BI_SERV], inf[BI_CHAN]):
            raw_peer_nick, message = print_msg.split('\t', 2)
            for t in taglist:
                if t.find("nick_") == 0:
                    ret_nick = t[5:].strip()
            if inf[BI_NICK] == ret_nick:
                acwee.prtAcPrivMsg(buffer, inf[BI_NICK], message, tags)
                return [ True, message ]

        return [ False, print_msg ]








#
#
#
#
#
#
# CALLBACKS
#
#
#
#
#
#
def ac_checktimer_cb(data, remaining_calls):
    weechat.prnt("", "timer! data=%s" % data)
#    global acProcess
#    acProcess.poll()
#    if acProcess.returncode is not None:
#        weechat.prnt("", "code is dead let's restart! data=%r" % acProcess.returncode)
#        ac_start_daemon()
#    weechat.prnt("", "timer! data=%r" % acProcess.returncode)
    return weechat.WEECHAT_RC_OK

#
#
# 
# PK commands
# 
# /pk gen 
# /pk ls 
# /pk rm
# /ac help
# /pk ===> DEFAULT BEHAVIOUR
#
#
#

#def cmd_pubkey_cb(data, dabuffer, args):
def pkCmd_CB(data, dabuffer, args):
    # /pk   ========> DEFAULT BEHAVIOUR (broadcast)
    # /pk ls
    # /pk rm <nick>
    # /pk gen

    # XXX TODO: that split(" ") create an issue with entropy than contain more
    # than one space, however we should not need it for pk
    cb_argv = args.split()
    cb_argc = len(cb_argv)

#    acwee.pmb(dabuffer, "ARGS[%d]: %r (raw:%s)\n", cb_argc, cb_argv, args)

    if cb_argc == 0:
        return pkCmdBroadcast(data, dabuffer, args)
    if cb_argc >= 1:
        cmd = cb_argv[0]
        newargv = " ".join(cb_argv[1:])
        if cmd == 'ls':
            return pkCmdList(data, dabuffer, newargv)
        elif cmd == 'gen':
            return pkCmdGeneratePair(data, dabuffer, newargv)
        elif cmd == "rm":
            return pkCmdDel(data, dabuffer, newargv)
        elif cmd == "help":
            return pkCmdHelp(data, dabuffer, newargv)
    return pkCmdBroadcast(data, dabuffer, newargv)

def pkCmdHelp(data, dabuffer, newargv):
    acwee.pmb(dabuffer, "$#%%$#@%%#%%@#$%%@#$%%@$#%%@#$ /pk help %%@#$%%#@$%%#@$%%@#$%%@#%%@#$%%@")
    acwee.pmb(dabuffer, "Public key commands:")
    acwee.pmb(dabuffer, "\t\t")
    acwee.pmb(dabuffer, "/pk help")
    acwee.pmb(dabuffer, "\t\tthis help")
    acwee.pmb(dabuffer, "\t\t")
    acwee.pmb(dabuffer, "/pk ls")
    acwee.pmb(dabuffer, "\t\tList all currently know registered (in 'ac' running context) public keys and personal keypairs.")
    acwee.pmb(dabuffer, "\t\texample: /pk ls")
    acwee.pmb(dabuffer, "\t\t")
    acwee.pmb(dabuffer, "/pk rm <nick>")
    acwee.pmb(dabuffer, "\t\tRemove the public(/priv) key of <nick>")
    acwee.pmb(dabuffer, "\t\texample: /pk rm jamboree")
    acwee.pmb(dabuffer, "\t\t")
    acwee.pmb(dabuffer, "/pk gen")
    acwee.pmb(dabuffer, "\t\tGenerate a personal ephemeral public/private key pair for secret key exchange,")
    acwee.pmb(dabuffer, "\t\tIt rely on Go's crypto/rand PRNG and use NaCL Curve 25519 go.crypto implementation")
    acwee.pmb(dabuffer, "\t\texample: /pk gen")
    acwee.pmb(dabuffer, "\t\t")
    acwee.pmb(dabuffer, "/pk")
    acwee.pmb(dabuffer, "\t\tBroadcast your public key in the current buffer (channel|query) using notice")
    acwee.pmb(dabuffer, "\t\texample: /pk")
    acwee.pmb(dabuffer, "\t\t")
    acwee.pmb(dabuffer, "$#%%$#@%%#%%@#$%%@#$%%@$#%%@#$%%@#$%%@#$%%@#$%%#@$%%#@$%%@#$%%@#%%@#$%%@")
    return weechat.WEECHAT_RC_OK

#
# PK generation
#

def pkCmdGeneratePair(data, dabuffer, args):
    # KEY INFOS..
    inf = ac_get_buflocalinfo(dabuffer)
    if len(inf[BI_NICK]) == 0 or len(inf[BI_SERV]) == 0:
        acwee.pmbac(dabuffer, "could not generate ephemeral key pair, you're connected nowhere!")
        acwee.pmbac(dabuffer, "remember your key pair is associated with your server/nickname pair")
        return weechat.WEECHAT_RC_OK

    # XXX TODO: TO CHANGE
#    userhost = "unavailable"
    userhost = ac_get_userinfo(dabuffer, inf[BI_NICK], inf[BI_CHAN], inf[BI_SERV])

#    weechat.prnt(dabuffer, "%sAC\tnick: %s" % ( weechat.color("yellow,blue"), nick))
#    weechat.prnt(dabuffer, "%sAC\tchannel: %s" % ( weechat.color("yellow,blue"), channel))
#    weechat.prnt(dabuffer, "%sAC\tserver: %s" % ( weechat.color("yellow,blue"), server))
#    weechat.prnt(dabuffer, "%sAC\tuserhost: %s" % ( weechat.color("yellow,blue"), userhost))
#    weechat.prnt(dabuffer, "%sAC\tplugin: %s" % ( weechat.color("yellow,blue"), plugin))
#    weechat.prnt(dabuffer, "%sAC\ttype: %s" % ( weechat.color("yellow,blue"), gtype))
#

    if ( inf[BI_TYPE] == "channel" or inf[BI_TYPE] == "private" ) and len(inf[BI_NICK]) > 0:
        myargs = { acwee.KEY_NICK:inf[BI_NICK], acwee.KEY_HOST:userhost, acwee.KEY_SERVER:inf[BI_SERV], acwee.KEY_BLOB:"" }
        ac_pkr, err = acwee.acRequest(acwee.ACMSG_TYPE_PK, acwee.ACMSG_SUBTYPE_PKGEN, myargs, acwee.BUF_SMALL)
        if ac_pkr and ac_pkr.bada == True:
            acwee.pmbac(dabuffer, "generated a new ECC 25519 public/private keypair ('/pk ls' to see it)")
#            acwee.pmb(dabuffer, "genkey rc: %s", str(ac_pkr.bada))
#            acwee.pmb(dabuffer, "genkey error_code: %s",  str(ac_pkr.error_code))
        else:
            acwee.pmbac(dabuffer, "could not generate key (%d -> check daemon logs?)!", ac_pkr.error_code)
        return weechat.WEECHAT_RC_OK
    acwee.pmbac(dabuffer, "could not generate key you are NOT in a (connected) channel/query buffer!")
    return weechat.WEECHAT_RC_OK


# 
# XXX TODO: we need to add the parsing of argument to allow one or several nicks!?
#
def pkCmdList(data, dabuffer, args):
    nick = weechat.buffer_get_string(dabuffer,"localvar_nick")
    gtype = weechat.buffer_get_string(dabuffer,"localvar_type")
    server = weechat.buffer_get_string(dabuffer,"localvar_server")

    if args <> None and len(args) > 0:
        myargs = { acwee.KEY_NICK:args, acwee.KEY_SERVER:server } 
    else: # XXX TODO: this is not clean...
        myargs = { acwee.KEY_SERVER:server } 

    ac_pkr, err = acwee.acRequest(acwee.ACMSG_TYPE_PK, acwee.ACMSG_SUBTYPE_PKLIST, myargs, acwee.BUF_LARGE)
    if ac_pkr:
        if len(ac_pkr.public_keys) > 0:
            for t in ac_pkr.public_keys:
                acwee.prtAcPk(dabuffer, t, nick)
        else:
            acwee.pmbac(dabuffer, "NO KEYS FOUND :(")
        return weechat.WEECHAT_RC_OK
    return weechat.WEECHAT_RC_ERROR

# 
# XXX TODO: we need to add the parsing of argument to allow one or several nicks!?
#
def pkCmdDel(data, dabuffer, args):
    nick = weechat.buffer_get_string(dabuffer,"localvar_nick")
    gtype = weechat.buffer_get_string(dabuffer,"localvar_type")
    server = weechat.buffer_get_string(dabuffer,"localvar_server")


    if args <> None and len(args) == 0:
        acwee.pmbac("look for some help, you don't understand what you want...")
        return weechat.WEECHAT_RC_OK

    myargs = { acwee.KEY_NICK:args, acwee.KEY_SERVER:server } 
    ac_pkr, err = acwee.acRequest(acwee.ACMSG_TYPE_PK, acwee.ACMSG_SUBTYPE_PKDEL, myargs, acwee.BUF_SMALL)
    if ac_pkr and ac_pkr.bada == True:
        acwee.pmbac(dabuffer, "'%s''s key removed", args)
    else:
        acwee.pmbac(dabuffer, "NO KEY FOUND :(")
    return weechat.WEECHAT_RC_OK

#
# broadcast key
#
# we do NOTICE for public key broadcast and for kex
#
def pkCmdBroadcast(data, dabuffer, args):

    inf = ac_get_buflocalinfo(dabuffer)
    # XXX TODO: check if channel or private message and IRC
    if inf and inf.has_key(BI_TYPE) and inf.has_key(BI_NICK) and inf.has_key(BI_SERV) and inf.has_key(BI_CHAN):

        # now request my key..
        myargs = { acwee.KEY_NICK:inf[BI_NICK], acwee.KEY_SERVER:inf[BI_SERV] } 
        ac_pkr, err = acwee.acRequest(acwee.ACMSG_TYPE_PK, acwee.ACMSG_SUBTYPE_PKLIST, myargs, acwee.BUF_LARGE)
        if ac_pkr and ac_pkr.bada == True:
            if len(ac_pkr.public_keys) == 1:
                for t in ac_pkr.public_keys:
                    acwee.pmbac(dabuffer, "broadcasting my key on %s", inf[BI_CHAN])
                    weechat.command(dabuffer, "/notice %s %s %s" % (inf[BI_CHAN], acKeyPrefix, t.pubkey))
                return weechat.WEECHAT_RC_OK
        acwee.pmbac(dabuffer, "NO KEY /pk gen first")
        return weechat.WEECHAT_RC_OK
    else:
        acwee.pmbac(dabuffer, "/pk only works in a channel/privmsg buffer")
        return weechat.WEECHAT_RC_OK



#
#
#
#
# 
# KEX implementation
# 
# /sk <nick>
# /sk add <entropy>
# /sk rm <hash>
# /sk use
# /sk ls ===> DEFAULT BEHAVIOUR
#
#
#
#
#

#def cmd_secretkey_cb(data, dabuffer, args):
def skCmd_CB(data, dabuffer, args):
    cb_argv = args.split()
    cb_argc = len(cb_argv)

#    acwee.pmb(dabuffer, "ARGS[%d]: %r (raw:%s)", cb_argc, cb_argv, args)
    if cb_argc == 0:
        return skCmdList(data, dabuffer, args)
    if cb_argc >= 1:
        newargv = " ".join(cb_argv[1:])
        cmd = cb_argv[0]
#        acwee.pmb(dabuffer, "CMD: %s NEWARGS: %s", cmd, newargv)
        if cmd == "gen":
            return skCmdAddKey(data, dabuffer, newargv)
        elif cmd == "rm":
            acwee.pmb(dabuffer, "not implemented yet!")
        elif cmd == "use":
            return skCmdUseKey(data, dabuffer, newargv)
        elif cmd == "ls":
            return skCmdList(data, dabuffer, newargv)
        elif cmd == "help":
            return skCmdHelp(data, dabuffer, newargv)
        elif cmd == "give":
            if len(newargv) > 0 and re.match(acNicknameRE, newargv[0], re.M) <> None:
                return skCmdSendKey(data, dabuffer, newargv)
    return skCmdList(data, dabuffer, args)

def skCmdHelp(data, dabuffer, newargv):
    acwee.pmb(dabuffer, "$#%%$#@%%#%%@#$%%@#$%%@$#%%@#$ /sk help %%@#$%%#@$%%#@$%%@#$%%@#%%@#$%%@")
    acwee.pmb(dabuffer, "Secret/Symmetric key commands:")
    acwee.pmb(dabuffer, "\t\t")
    acwee.pmb(dabuffer, "/sk help")
    acwee.pmb(dabuffer, "\t\tthis help")
    acwee.pmb(dabuffer, "\t\t")
    acwee.pmb(dabuffer, "/sk ls")
    acwee.pmb(dabuffer, "\t\tList all currently know registered AC active weechat buffers.")
    acwee.pmb(dabuffer, "\t\texample: /sk ls")
    acwee.pmb(dabuffer, "\t\t")
#    acwee.pmb(dabuffer, "/sk rm <nick>")
#    acwee.pmb(dabuffer, "\t\tRemove the public(/priv) key of <nick>")
#    acwee.pmb(dabuffer, "\t\texample: /pk rm jamboree")
    acwee.pmb(dabuffer, "/sk gen <channel password/user additionnal entropy>")
    acwee.pmb(dabuffer, "\t\tGenerate a secret/symmetric key  for the current buffer and enable crypto immediately.")
    acwee.pmb(dabuffer, "\t\tIt rely on go.crypto pbkdf2/hkdf/SHA3-256 and Go's crypto/rand implementation.")
    acwee.pmb(dabuffer, "\t\tparam1 <- PBKDF2(userinput, salt:crypto_rand, iter:4096, len:32bytes, hash:SHA3-256).")
    acwee.pmb(dabuffer, "\t\tsecret <- HKDF(hash:SHA3-256, secret:param1, salt:crypto_rand, info:\"serv:nick:channel\").")
    acwee.pmb(dabuffer, "\t\texample: /sk gen 43209841324k1jlkj4123lk4jlkjln nm154mn43m2n5,43mn")
    acwee.pmb(dabuffer, "\t\t")
    acwee.pmb(dabuffer, "/sk give <nickname>")
    acwee.pmb(dabuffer, "\t\tPack and authenticate current buffer known/defined secret/symmetric key into an AC kex payload for <nickname>")
    acwee.pmb(dabuffer, "\t\tyou MUST have a valid ephemeral keypair with your nickname/server generated (e.g /pk gen) and <nickname>'s public key")
    acwee.pmb(dabuffer, "\t\talso to be able to authenticate your AC kex payload, nickname's MUST have your public key (/pk)")
    acwee.pmb(dabuffer, "\t\tthis ensure a relatively safe transfer of the secret (channel) key to another peer/individual using AC")
    acwee.pmb(dabuffer, "\t\tbuffer will display a red bar when you're encrypting your chats and the \"N: <int64>\" is the current Nonce Value (should ALWAYS increase)")
    acwee.pmb(dabuffer, "\t\tWARNING: AC DO NOT have PFS as it is for multiparty encrypted chats and IRC have buffer size limitations, hence rekey when Nonce value reach a few thousands messages")
    acwee.pmb(dabuffer, "\t\tKex format:")
    acwee.pmb(dabuffer, "\t\tNonceAuth <-SHA3( 'channel:my_nick:peer_nick:nonce_ctr:hdr' )")
    acwee.pmb(dabuffer, "\t\tKexBox    <- B64( 'KX'+'nonce_ctr'+Curve25519_box( peer_publickey, my_privatekey, NonceAuth, zlib( secret ) ) )")
    acwee.pmb(dabuffer, "\t\texample: /sk give jamboree")
    acwee.pmb(dabuffer, "\t\t")
    acwee.pmb(dabuffer, "/sk use")
    acwee.pmb(dabuffer, "\t\tAuthenticate, unpack & use the last AC kex (Key EXchange) payload received for this buffer (channel/query) by <nickname>")
    acwee.pmb(dabuffer, "\t\tyou MUST have the sender's (<nickname>) public key otherwise the key exchange will just fail.")
    #using your current public public key in the current buffer (channel|query) using notice")
    acwee.pmb(dabuffer, "\t\texample: /pk")
    acwee.pmb(dabuffer, "\t\t")
    acwee.pmb(dabuffer, "$#%%$#@%%#%%@#$%%@#$%%@$#%%@#$%%@#$%%@#$%%@#$%%#@$%%#@$%%@#$%%@#%%@#$%%@")
    return weechat.WEECHAT_RC_OK



def skCmdSendKey(data, dabuffer, args):
    cb_argv = args.split()
    cb_argc = len(cb_argv)
    # the command has only one argument.
    if cb_argc != 1:
        return weechat.WEECHAT_RC_ERROR
    # peer nickname
    peer = cb_argv[0]
    # my nickname is in inf..
#    acwee.pmb(dabuffer, "SENDKEY ARGS: %s", args)
#
#    weechat.prnt(dabuffer, "%sAC\tSENDKEY ARGS: %s" % (SCRIPT_COLOR, args))
#
    inf = ac_get_buflocalinfo(dabuffer)
    if inf and inf.has_key(BI_NICK) and inf.has_key(BI_CHAN) and inf.has_key(BI_SERV) and inf.has_key(BI_TYPE) and inf[BI_PLUG] == "irc":
#        acwee.pmb(dabuffer, "mynick:%s peer_nick:%s chan: %s serv:%s", inf[BI_NICK], peer, inf[BI_CHAN], inf[BI_SERV])
#        weechat.prnt(dabuffer, "%sAC\tmynick:%s peer_nick:%s chan: %s serv:%s" % (SCRIPT_COLOR, inf[BI_NICK], peer, inf[BI_CHAN], inf[BI_SERV]))
#
        myargs = { acwee.KEY_MYNICK:inf[BI_NICK], acwee.KEY_PEERNICK:peer, acwee.KEY_CHANNEL:inf[BI_CHAN], acwee.KEY_SERVER:inf[BI_SERV] } 
#        acblob = ac_msg(ACMSG_TYPE_KEX, ACMSG_SUBTYPE_KXPACK, myargs)
#        ac_kxr, err = ac_request(acblob, ACMSG_TYPE_KEX, BUF_LARGE)
        ac_kxr, err = acwee.acRequest(acwee.ACMSG_TYPE_KEX, acwee.ACMSG_SUBTYPE_KXPACK, myargs, acwee.BUF_LARGE)
        if ac_kxr:
            if ac_kxr.bada == True:
                acwee.pmbac(dabuffer, "sendkey %s -> %s", args, ac_kxr.blob)
#                weechat.prnt(dabuffer, "%sAC\tsendkey %s -> %s" % ( SCRIPT_COLOR, args, ac_kxr.blob))
                # patch to NOTICE in the buffer..
                weechat.command(dabuffer, "/notice %s %s%s> %s" % (inf[BI_CHAN], acKexPrefix, peer, ac_kxr.blob))
                return weechat.WEECHAT_RC_OK
    return weechat.WEECHAT_RC_ERROR


# XXX TODO: more sanity checks...
def skCmdAddKey(data, dabuffer, args):
    cb_argv = args.split()
    cb_argc = len(cb_argv)
    if cb_argc <= 0:
        return weechat.WEECHAT_RC_ERROR

    inf = ac_get_buflocalinfo(dabuffer)
    if inf and inf.has_key(BUF_INFO_NICK) and inf.has_key(BUF_INFO_CHAN) and inf.has_key(BUF_INFO_SERV) and inf.has_key(BI_TYPE):
        if inf[BI_TYPE] == "channel" or inf[BI_TYPE] == "private":
            myargs = { acwee.KEY_NICK:inf[BI_NICK], acwee.KEY_BLOB:args, acwee.KEY_CHANNEL:inf[BI_CHAN], acwee.KEY_SERVER:inf[BI_SERV] } 
            ac_ctr, err = acwee.acRequest(acwee.ACMSG_TYPE_CRYPTO, acwee.ACMSG_SUBTYPE_CTADD, myargs, acwee.BUF_LARGE)
            if ac_ctr:
                if ac_ctr.bada == True:
#                return acwee.acEnable(dabuffer, inf[BI_SERV], inf[BI_CHAN])
                    return acCmdToggle(data, dabuffer, "")
    acwee.pmbac(dabuffer, "make sure the buffer you want to add a key to is either a query or a channel buffer, here is : '%s'", inf[BI_TYPE])
    return weechat.WEECHAT_RC_ERROR



def skCmdUseKey(data, dabuffer, args):
    inf = ac_get_buflocalinfo(dabuffer)
    if inf and inf.has_key(BUF_INFO_CHAN) and inf.has_key(BUF_INFO_SERV):
        kexinfo = acwee.rcvKexPop(inf[BI_SERV], inf[BI_CHAN]);
        # TODO: better sanity checks..
        if kexinfo:
            myargs = { acwee.KEY_MYNICK:kexinfo[0], acwee.KEY_PEERNICK:kexinfo[1], acwee.KEY_CHANNEL:kexinfo[2], acwee.KEY_SERVER:kexinfo[3], acwee.KEY_BLOB:kexinfo[4] } 
            ac_kxr, err = acwee.acRequest(acwee.ACMSG_TYPE_KEX, acwee.ACMSG_SUBTYPE_KXUNPACK, myargs, acwee.BUF_LARGE)
            if ac_kxr and err is None:
                if ac_kxr.bada == True:
                    acwee.pmbac(dabuffer, "using key received from %s @ [%s/%s]", kexinfo[1], kexinfo[2], kexinfo[3])
                    acwee.acEnable(dabuffer, inf[BI_SERV], inf[BI_CHAN])
                    # nonce display/update..
                    acwee.acUpdNonce(inf[BI_SERV], inf[BI_CHAN], ac_kxr.nonce)
                else:
                    acwee.pmbac(dabuffer, "invalid key exchange received from %s @ [%s/%s]", kexinfo[1], kexinfo[2], kexinfo[3])
            else:
                acwee.pmbac(dabuffer, "AC proto communication error err:  %s", str(err))
            return weechat.WEECHAT_RC_OK
        else:
            acwee.pmbac(dabuffer, "no KeX payload to process")
    else:
        acwee.pmbac(dabuffer, "you're willing to use a key, but may be in the wrong place! (hint: the buffer where you received the key)")
    return weechat.WEECHAT_RC_OK



# XXX TODO this is a debug command so to remove anyway...
def skCmdList(data, dabuffer, args):
#    acwee = data
    # XXX using acHashList
    acwee.acHashList(dabuffer)
    return weechat.WEECHAT_RC_OK



# 
# AC commands
# 
# /ac save <filename>
# /ac load <filename>
# /ac ping
# /ac help
# /ac ===> DEFAULT BEHAVIOUR

def acCmd_CB(data, dabuffer, args):
    cb_argv = args.split()
    cb_argc = len(cb_argv)

#    acwee.pmb(dabuffer, "ARGS[%d]: %r (raw:%s)", cb_argc, cb_argv, args)
    if cb_argc == 0:
        return acCmdToggle(data, dabuffer, args)
    if cb_argc >= 1:
        newargv = " ".join(cb_argv[1:])
        cmd = cb_argv[0]
#        acwee.pmb(dabuffer, "CMD: %s NEWARGS: %s", cmd, newargv)
        if cmd == "save":
            return acCmdSave(data, dabuffer, newargv)
        elif cmd == "load":
            return acCmdLoad(data, dabuffer, newargv)
        elif cmd == "help":
            return acCmdHelp(data, dabuffer, args)
        else:
            return acCmdToggle(data, dabuffer, args)


def acCmdSave(data, dabuffer, args):
    cb_argv = args.split()
    cb_argc = len(cb_argv)

    
    if cb_argc == 0:
        acwee.pmbac(dabuffer, "no filename given for saving! /ac save <filename> or /ac help for more information")
    else:
        acwee.pmbac(dabuffer, "NOW SAVING on %s!!", cb_argv[0])
        myargs = { acwee.KEY_FILENAME:cb_argv[0] } 
        ac_ctlr, err = acwee.acRequest(acwee.ACMSG_TYPE_CTL, acwee.ACMSG_SUBTYPE_CTLSAVE, myargs, acwee.BUF_LARGE)
        if ac_ctlr:
            if ac_ctlr.bada == True:
                acwee.pmbac(dabuffer, "saved in  [%s]", cb_argv[0])

    return weechat.WEECHAT_RC_OK

def acCmdLoad(data, dabuffer, args):
    cb_argv = args.split()
    cb_argc = len(cb_argv)

    
    if cb_argc == 0:
        acwee.pmbac(dabuffer, "no filename given for loading! /ac load <filename> or /ac help for more information")
    else:
        acwee.pmbac(dabuffer, "NOW LOADING from %s!!", cb_argv[0])
        myargs = { acwee.KEY_FILENAME:cb_argv[0] } 
        ac_ctlr, err = acwee.acRequest(acwee.ACMSG_TYPE_CTL, acwee.ACMSG_SUBTYPE_CTLLOAD, myargs, acwee.BUF_LARGE)
        if ac_ctlr:
            if ac_ctlr.bada == True:
                acwee.pmbac(dabuffer, "saved in  [%s]", cb_argv[0])
    return weechat.WEECHAT_RC_OK

def acCmdToggle(data, dabuffer, args):
    inf = ac_get_buflocalinfo(dabuffer)
    chanRetObj = re.match(acChannelRE, inf[BI_CHAN], re.M)
    nickRetObj = re.match(acNicknameRE, inf[BI_CHAN], re.M)
#    print chanRetObj
#    print nickRetObj
    if inf and inf.has_key(BI_CHAN) and inf.has_key(BI_SERV) and inf.has_key(BI_TYPE) and len(inf[BI_CHAN]) > 0 and len(inf[BI_SERV]) > 0 and (inf[BI_TYPE] == "channel" or inf[BI_TYPE] == "private") and (chanRetObj <> None or nickRetObj <> None):
        if acwee.isAcEnabled(inf[BI_SERV], inf[BI_CHAN]):
            # XXX using acEnable or acDisable here..
            acwee.acDisable(dabuffer, inf[BI_SERV], inf[BI_CHAN])
        else:
            acwee.acEnable(dabuffer, inf[BI_SERV], inf[BI_CHAN])
    else:
        acwee.pmbac(dabuffer, "cannot encrypt this buffer...")
    return weechat.WEECHAT_RC_OK

def acCmdHelp(data, dabuffer, args):
    #acwee = data
    acwee.pmb(dabuffer, "$#%%$#@%%#%%@#$%%@#$%%@$#%%@#$ /ac help %%@#$%%#@$%%#@$%%@#$%%@#%%@#$%%@")
    acwee.pmb(dabuffer, "args: %s", args)
    acwee.pmb(dabuffer, "/pk [<cmd>]\tpublic key commands")
    acwee.pmb(dabuffer, "where <cmd> is")
    acwee.pmb(dabuffer, "\t\thelp      :\thelp/examples about pk (Public Key)")
    acwee.pmb(dabuffer, "\t\tls        :\tlist pk(/sk) key(s)")
    acwee.pmb(dabuffer, "\t\trm <nick> :\tdel pk(/sk) key(s)")
    acwee.pmb(dabuffer, "\t\tgen       :\tgenerate my pk pair")
    acwee.pmb(dabuffer, "\t\t<empty>   :\tbroadcast my pk on the current channel/query buffer")
    acwee.pmb(dabuffer, "/sk [<cmd>|nick]\tsecret key commands")
    acwee.pmb(dabuffer, "where <cmd> is")
    acwee.pmb(dabuffer, "\t\thelp                :\thelp/examples about sk (Secret Key)")
    acwee.pmb(dabuffer, "\t\tls                  :\tlist current secret key(s)")
    acwee.pmb(dabuffer, "\t\tgen <entropy bytes> :\tPBKDF2() generate current buffer secret key")
    acwee.pmb(dabuffer, "\t\trm <nick>           :\tremove associated secret key")
    acwee.pmb(dabuffer, "\t\tuse                 :\tuse Key Exchange secret key received on this buffer (u need sender's public key)")
    acwee.pmb(dabuffer, "\t\tgive <nick>         :\tsend Key Exchange secret key with <nick> (u need <nick>'s public key)")
    acwee.pmb(dabuffer, "/ac [<cmd>]\tencryption control")
    acwee.pmb(dabuffer, "\t\thelp                :\thelp about ac (this help)")
    acwee.pmb(dabuffer, "\t\t<empty>   :\tenable/disable encryption in the current buffer (channel/query)")
    # /ac           : enable/disable buffer (chan/query) encryption
    # /ac help      : help on ac
    # /ac stat      : daemon stat + heartbeat stat
    # /ac bah       : rekey/reshuffle the internal memory protection
    acwee.pmb(dabuffer, "$#%%$#@%%#%%@#$%%@#$%%@$#%%@#$%%@#$%%@#$%%@#$%%#@$%%#@$%%@#$%%@#%%@#$%%@")

#    weechat.prnt(dabuffer, "%sAC\tAC help:%s" % ( SCRIPT_COLOR, args))
#    weechat.prnt(dabuffer, "%sAC\t/pk\tbroadcast our public key" % ( SCRIPT_COLOR ))
#    weechat.prnt(dabuffer, "%sAC\t/pkgen\tgenerate our key pair" % ( SCRIPT_COLOR ))
#    weechat.prnt(dabuffer, "%sAC\t/pklist\tlist running public keys" % ( SCRIPT_COLOR ))
#    weechat.prnt(dabuffer, "%sAC\t/sk <nick>\tsend #channel key to <nick>" % ( SCRIPT_COLOR ))
#    weechat.prnt(dabuffer, "%sAC\t/skadd <entropy>\tcreate #channel key" % ( SCRIPT_COLOR ))
#    weechat.prnt(dabuffer, "%sAC\t/skuse\tuse/accept the key that has been received on the current buffer" % ( SCRIPT_COLOR ))
#    weechat.prnt(dabuffer, "%sAC\taliases:" % (SCRIPT_COLOR))

    return weechat.WEECHAT_RC_OK



#
# SIGNAL CALLBACKS
#

#
# may be we can handle that using signals instead of print!!!
#
def signal_privmsg_cb(data, signal, signal_data):
    # signal is for example: "freenode,irc_in2_join"
    # signal_data is IRC message, for example: ":nick!user@host JOIN :#channel"
    nick = weechat.info_get("irc_nick_from_host", signal_data)
    server = signal.split(",")[0]
    channel = signal_data.split(":")[-1]
    buffer = weechat.info_get("irc_buffer", "%s,%s" % (server, channel))
    if buffer:
        weechat.prnt(buffer, "Eheh, %s has joined this channel!" % nick)
    return weechat.WEECHAT_RC_OK



#
#
# XXX TEMPORARY before being moved to utils functions..
# TODO: 
# - kex blob too small?!?
# - peernick or kex_nick on the channel? no -> invalid!
# - peernick == kex_nick ?!? yes -> weird!! invalid!
# - kex_nick == me, peernick public key present?!? -> no?! -> we cannot unpack can we?! ask user to pubkey..
#
# we return TRUE or FALSE if false we just display an error message on the buffer and return FALSE
#
def kex_lame_check(buffer, mynick, peernick, kex_nick, kex_blob, info):
    if len(kex_blob) < 90:
        acwee.pmbac(buffer, "Key Exchange attempt from %s [%s/%s] look suspicious: weird length.. -> ignoring!", peernick, info[BI_CHAN], info[BI_SERV])
#        weechat.prnt(buffer, "%sAC\tKey Exchange attempt from %s [%s/%s] look suspicious: weird length.. -> ignoring!" % ( SCRIPT_COLOR, peernick, info[BI_CHAN], info[BI_SERV]) )
        return False
    if peernick == kex_nick:
        acwee.pmbac(buffer, "Key Exchange attempt from %s [%s/%s] look suspicious: sending to oneself -> ignoring!", peernick, info[BI_CHAN], info[BI_SERV])
        return False
    return True


# this is what we get... for CHANNEL
#: stdout/stderr: string: croute | <acpk> qDtHEHjaOnn41qNtJqKuq1r7l0W9PyWk+fvP5Y3i5olWqhdc9sc62gMCAAD//yrCEHg=
#: stdout/stderr: data: proutprout
#: stdout/stderr: modifier: weechat_print
#: stdout/stderr: modifier_data: irc;freenode.#crutcruton;irc_privmsg,notify_message,prefix_nick_default,nick_croute,log1
#
# this is what we get... for PRIVATE
#: stdout/stderr: string: croute | <acpk> prout
#: stdout/stderr: data: proutprout
#: stdout/stderr: modifier: weechat_print
#: stdout/stderr: modifier_data: irc;freenode.croute;irc_privmsg,notify_private,prefix_nick_default,nick_croute,log1
#
#
# we use this hook for handling Public Key messages and Key Exchange Messages...
# for hanling <acpk> and <ackx> messages...
#
# XXX TODO: bug on freenode to investigate...
#
#
MODIFIER_SPLIT = ';'

# [ True/False, msg_type, nickname, raw_message, blob index, opt ]
MDIDX_RET = 0
MDIDX_TYPE = 1
MDIDX_NICK = 2
MDIDX_RMSG = 3
MDIDX_BINDEX = 4
# need to add the buffer...
MDIDX_OPT = 5
MDIDX_BUFFER = 6

# XXX TODO: i need a SERIOUS amount of docs otherwise this will be unmaintanable...
# all these data gathering tricks are to be known and to be followed based on weechat dev..
# long process to reach a reliable/production ready code...
def printmsg_modifier_cb(data, modifier, modifier_data, msg_string):
#    print "HERE IN PRINTMSG MODIFIER"
#    print "printmsg_modifier_cb()"
#    print "DATA:"
#    print data
#    print "MODIFIER:"
#    print modifier
#    print "MODIFIER_DATA:"
#    print modifier_data
#    print "MSG_STRING:"
#    print msg_string

    retval = acMessageParsePrintmsg(modifier_data, msg_string)
    if retval[0] is True:
        return ""
    return msg_string

#
# for handling <ac> messages...
#
# ac_message_parse_irc return [ True/False, Channel/Destination, Message ]
def privmsg_out_modifier_cb(data, modifier, modifier_data, msg_string):
#    print "modifier: %s" % str(modifier)
#    print "modifier_data: %s" % str(modifier_data)
#    print "string: %s" % msg_string
##    ret_string = msg_string
#    print "privmsg_out_modifier_cb():"
#    print "data: %s" % data
#    print "modifier: %s" % str(modifier)
#    print "modifier_data: %s" % str(modifier_data)
#    print "string: %s" % msg_string
#    print msg_string
    parsed = weechat.info_get_hashtable("irc_message_parse", { "message": msg_string, "server": modifier_data })
#    print "PARSED DICT"
#    print parsed

    if parsed.has_key(HPARSE_CHAN) and parsed.has_key(HPARSE_ARGS):
#        peer_nick = parsed[HPARSE_NICK]
#        peer_host = parsed[HPARSE_HOST].split('!', 1)[1].strip()
        channel = parsed[HPARSE_CHAN]
        server = modifier_data
        out_msg = parsed[HPARSE_ARGS].split(':',1)[1]
        # XXX TODO why do I strip() ?!?
#        out_msg = parsed[HPARSE_ARGS].split(':',1)[1].strip()

#        print "CHANNEL:"
#        print channel
#        print "SERVER:"
#        print server
#        print "OUT MSG:"
#        print out_msg
        # XXX TODO: force to create buffer when there is none for a pk message received.. and display in that buffer..
        # XXX TODO: sanity checks!! error handling!!
        buffer = weechat.info_get("irc_buffer", "%s,%s" % (server, channel))
        inf = ac_get_buflocalinfo(buffer)

        # my nick..
        my_nick = inf[BI_NICK]

#XXX TODO: this is VERY UNCLEAR... i need to handle error correctly but should be SAFE for now...
#XXX TODO: use isAcEnabled ?
#        if acCipherReady.has_key(keyBlobHash) and acCipherReady[keyBlobHash] is True:
        if acwee.isAcEnabled(server, channel):
            myargs = { acwee.KEY_MYNICK:my_nick, acwee.KEY_CHANNEL:channel, acwee.KEY_SERVER:server, acwee.KEY_BLOB:out_msg }
            try:
                ac_ctr, err = acwee.acRequest(acwee.ACMSG_TYPE_CRYPTO, acwee.ACMSG_SUBTYPE_CTSEAL, myargs, acwee.BUF_LARGE)
            except Exception as e:
                acwee.pmbac(buffer, "!WARNING!\tMESSAGE NOT SENT: '%s' [NO ENCRYPTOR]", out_msg)
                acwee.pmbac(buffer, "!WARNING!\tERROR: %s", str(e))
                return ""
            if ac_ctr and ac_ctr.bada == True:
                # XXX multiple message if the message is too long to fit in one
                # reply when it's packed.
                for tmp_msg in ac_ctr.blob:
                    acwee.acUpdNonce(server, channel, ac_ctr.nonce)
#                    tmp_msg = blobs.pop()
                    weechat.command(buffer, "/quote PRIVMSG %s :%s %s" % (channel, acCipherPrefix, tmp_msg))
#                "PRIVMSG "+channel+" :"+"<ac> "+ac_ctr.blob
#                return "PRIVMSG "+channel+" :"+"<ac> "+blobs[0]
                return ""
            else:
                acwee.pmbac(buffer, "!WARNING!\tMESSAGE NOT SENT: '%s' [CANNOT ENCRYPT:%d]", out_msg, ac_ctr.error_code)
                return ""
#        acwee.pmbac(buffer, "BLEH BLEH BLEH")
        return msg_string


# python: stdout/stderr: notice_in_modifier_cb():
# python: stdout/stderr: data: proutprout
# python: stdout/stderr: modifier: irc_in_NOTICE
# python: stdout/stderr: modifier_data: 127.0.0.1
# python: stdout/stderr: string: :eaueau!~eau@127.0.0.1 NOTICE #crutcruton :<acpk> grnnunjaev6U93HC33mnz1qs215lvz9TeHONXsiVH5Ksh/ZN1N0SZAwIAAD//zK2EPM=
# python: stdout/stderr: PARSED DICT
# python: stdout/stderr: {'tags': '', 'message_without_tags': ':eaueau!~eau@127.0.0.1 NOTICE #crutcruton :<acpk> grnnunjaev6U93HC33mnz1qs215lvz9TeHONXsiVH5Ksh/ZN1N0SZAwIAAD//zK2EPM=', 'nick': 'eaueau', 'host':
#                         'eaueau!~eau@127.0.0.1', 'command': 'NOTICE', 'arguments': '#crutcruton :<acpk> grnnunjaev6U93HC33mnz1qs215lvz9TeHONXsiVH5Ksh/ZN1N0SZAwIAAD//zK2EPM=', 'channel': '#crutcruton'}

HPARSE_NICK = "nick"
HPARSE_HOST = "host"
HPARSE_ARGS = "arguments"
HPARSE_CHAN = "channel"
HPARSE_CMD = "command"


def notice_in_modifier_cb(data, modifier, modifier_data, msg_string):
    ret_string = msg_string
#    print "notice_in_modifier_cb():"
#    print "data: %s" % data
#    print "modifier: %s" % str(modifier)
#    print "modifier_data: %s" % str(modifier_data)
#    print "string: %s" % str(msg_string)
#    print msg_string
    parsed = weechat.info_get_hashtable("irc_message_parse", { "message": msg_string, "server": modifier_data })
#    print "PARSED DICT"
#    print parsed
    if parsed.has_key(HPARSE_NICK) and parsed.has_key(HPARSE_HOST) and parsed.has_key(HPARSE_CHAN) and parsed.has_key(HPARSE_ARGS):
        peer_nick = parsed[HPARSE_NICK]
        peer_host = parsed[HPARSE_HOST].split('!', 1).pop().strip()
        channel = parsed[HPARSE_CHAN]

        # XXX in normal situation we receive :
        # ':podom!~eau@127.0.0.1 NOTICE #chan :<ackx:eau> 7xpo....'
        # in private message we receive :
        # ':podom!~eau@127.0.0.1 NOTICE eau :<ackx:eau> 7xpo
        # while the buffer is toward the peer_nick
        # that's an ugly way to solve it, we need a way to find our nickname or to find the buffer based on peer_nick..

        
        # XXX verify if the channel name is a nickname or a channel name, it is equivalent to if channel[0] != '#':
        retObj = re.match(acChannelRE, channel, re.M)
        if retObj == None:
            channel = peer_nick
        server = modifier_data
        peer_msg = parsed[HPARSE_ARGS].split(':',1)[1].strip()

        # XXX TODO: force to create buffer when there is none for a pk message received.. and display in that buffer..
        # XXX TODO: sanity checks!! error handling!!
        buffer = weechat.info_get("irc_buffer", "%s,%s" % (server, channel))
        inf = ac_get_buflocalinfo(buffer)

        # my nick..
        my_nick = inf[BI_NICK]

        # in peer_msg we have : '<acpk> grnnunjaev6U93HC33mnz1qs215lvz9TeHONXsiVH5Ksh/ZN1N0SZAwIAAD//zK2EPM='
        # check if channel == peer_nick -> message to myself..
        # check if buffer exist

        # <acpk> messages... need to strengthen the parsing/verification..
        if peer_msg.find(acKeyPrefix) == 0 and len(peer_msg) > len(acKeyPrefix)+1:
            msg_blob = peer_msg[len(acKeyPrefix):].strip()
            if ac_isb64(msg_blob) is False:
                acwee.pmbac(buffer, "%s invalid public key (b64) payload broadcasted [%s/%s]!", peer_nick, peer_nick, channel) 
                return ret_string
            myargs = { acwee.KEY_NICK:peer_nick, acwee.KEY_HOST:peer_host, acwee.KEY_SERVER:server, acwee.KEY_BLOB:msg_blob }
            try:
                ac_pkr, err = acwee.acRequest(acwee.ACMSG_TYPE_PK, acwee.ACMSG_SUBTYPE_PKADD, myargs, acwee.BUF_SMALL)
            except Exception as e:
                acwee.pmbac(buffer, "!WARNING!\tMESSAGE NOT SENT: '%s' [NO ENCRYPTOR:%s]", out_msg, str(e))
            if ac_pkr and ac_pkr.bada == True:
                acwee.pmbac(buffer, "%s broadcasted his public key [%s/%s] ", peer_nick, peer_nick, channel)
                ret_string = ""
            else:
                acwee.pmbac(buffer, "%s invalid public key payload broadcasted [%s/%s]!", peer_nick, peer_nick, channel)
            return ret_string
        # <ackx:*> messages... need to strengthen the parsing/verification..
        if peer_msg.find(acKexPrefix) == 0 and len(peer_msg) > 52+len(acKexPrefix)+1:
#            weechat.prnt(buffer, "%sAC\tthis is it KEX EXCHANGE DETECTED" % (SCRIPT_COLOR))
            retObj = re.match(acKexRE, peer_msg, re.M)
            if retObj:
                kex_blob = retObj.group(2).strip()
                kex_nick = retObj.group(1).strip()
                if not kex_lame_check(buffer, my_nick, peer_nick, kex_nick, kex_blob, inf):
                    return ret_string
                if kex_nick == my_nick:
                    # XXX TODO: here we will process the UNPACKing... :)
                    # XXX using rcvKexPush
                    acwee.rcvKexPush(server, channel, [ my_nick, peer_nick, channel, server, kex_blob ] )
                    acwee.pmbac(buffer, "%s <KEX:%s/%s> TO YOU %%$!%%$\%%!#@!#$ ACCEPT IT ?!", peer_nick, channel, server )
                    acwee.pmbac(buffer, "type '/sk use' in this buffer to use it!")

                else:
                    acwee.pmbac(buffer, "%s -> <KEX:%s/%s> -> %s", peer_nick, channel, server, kex_nick)
                return ""
    return ret_string

# PRIVATE MESSAGE
# python: stdout/stderr: :eau!~eau@127.0.0.1 PRIVMSG podom :<ac> KZqPkAMAAADrccHoxpbajKmB2i4YEiHNWI7Qz3U0cdF19785dZm9KxQ9qkEBzKS5HvlZzLAQIRj3
# python: stdout/stderr: PARSED DICT
# python: stdout/stderr: {'tags': '', 'message_without_tags': ':eau!~eau@127.0.0.1 PRIVMSG podom :<ac> KZqPkAMAAADrccHoxpbajKmB2i4YEiHNWI7Qz3U0cdF19785dZm9KxQ9qkEBzKS5HvlZzLAQIRj3', 'nick': 'eau', 'host':
#                               'eau!~eau@127.0.0.1', 'command': 'PRIVMSG', 'arguments': 'podom :<ac> KZqPkAMAAADrccHoxpbajKmB2i4YEiHNWI7Qz3U0cdF19785dZm9KxQ9qkEBzKS5HvlZzLAQIRj3', 'channel': 'podom'}

# CHANNEL MESSAGE
# python: stdout/stderr: :eau!~eau@127.0.0.1 PRIVMSG #crutcruton :<ac> iRCtMgMAAAClI4DN7k6WQL2TC01bTpximBvG7aFN/4Qgz73E7ygKbMAO
# python: stdout/stderr: PARSED DICT
# python: stdout/stderr: {'tags': '', 'message_without_tags': ':eau!~eau@127.0.0.1 PRIVMSG #crutcruton :<ac> iRCtMgMAAAClI4DN7k6WQL2TC01bTpximBvG7aFN/4Qgz73E7ygKbMAO', 'nick': 'eau', 'host': 'eau!~eau@127.0.0.1',
#                               'command': 'PRIVMSG', 'arguments': '#crutcruton :<ac> iRCtMgMAAAClI4DN7k6WQL2TC01bTpximBvG7aFN/4Qgz73E7ygKbMAO', 'channel': '#crutcruton'}





# from podom to eau
# python: stdout/stderr: PARSED DICT 
# python: stdout/stderr: {'tags': '', 'message_without_tags': 'PRIVMSG eau :testprout', 'nick': 'eau', 'host': '', 'command': 'PRIVMSG', 'arguments': 'eau :testprout', 'channel': 'eau'}
# python: stdout/stderr: CTSEAL args:
# python: stdout/stderr: {'serv': '127.0.0.1', 'mynick': 'podom', 'chan': 'eau', 'blob': 'testprout'}


# [+] HandleACMsg() -> Unmarshal()
# this is a CipherText Message
# HandleACPkMsg()
# SEAL CT Message:!
# CTSEAL Message: let's give the key
# from myNick: podom
# blob: testprout
# channel: eau
# ===---=-=-=--==- GetSKMapEntry (serv: 127.0.0.1 channel: eau) ! skmap: 0xc21001ea50 ok: true --==-=---=-=-=-==-
# ===---=-=-=--==- GetSKMapEntry (serv: 127.0.0.1 channel: eau) ! val: 0xc210039600 ok: true --==-=---=-=-=-==-
# [+] CreateACMessage: is eau a valid channel: false
# [+] CreateACMessage: not a channel, private conversation let's use this: podom=eau
# ENCODE NONCE HEX: 706f646f6d3d6561753a706f646f6d3a030000003aa3baadb0 (podom=eau:podom:03000000:a3baadb0)

# received by eau
#
#
# python: stdout/stderr: MSG+STRING:                                                                                                                                                                                 
# python: stdout/stderr: :podom!~eau@127.0.0.1 PRIVMSG eau :<ac> o7qtsAMAAAAMbcXLb45sHxDojxDcn95HidgFAItNlSWs2w1I+OUFRZdrs7wV                                                                                        
# python: stdout/stderr: PARSED DICT                                                                                                                                                                                 
# python: stdout/stderr: {'tags': '', 'message_without_tags': ':podom!~eau@127.0.0.1 PRIVMSG eau :<ac> o7qtsAMAAAAMbcXLb45sHxDojxDcn95HidgFAItNlSWs2w1I+OUFRZdrs7wV', 'nick': 'podom', 'host': 'podom!~eau@127.0.0.1',
#                         'command': 'PRIVMSG', 'arguments': 'eau :<ac> o7qtsAMAAAAMbcXLb45sHxDojxDcn95HidgFAItNlSWs2w1I+OUFRZdrs7wV', 'channel': 'eau'}
# python: stdout/stderr: CTOPEN args:
# python: stdout/stderr: {'serv': '127.0.0.1', 'peernick': 'podom', 'chan': 'podom', 'blob': 'o7qtsAMAAAAMbcXLb45sHxDojxDcn95HidgFAItNlSWs2w1I+OUFRZdrs7wV'}

# [+] HandleACMsg() -> Unmarshal()
# this is a CipherText Message
# HandleACPkMsg()
# OPEN CT Message:!
# CTOPEN Message: let's give the key
# from nick: podom
# blob: o7qtsAMAAAAMbcXLb45sHxDojxDcn95HidgFAItNlSWs2w1I+OUFRZdrs7wV
# channel: podom
# ===---=-=-=--==- GetSKMapEntry (serv: 127.0.0.1 channel: podom) ! skmap: 0xc21001ea50 ok: true --==-=---=-=-=-==-
# ===---=-=-=--==- GetSKMapEntry (serv: 127.0.0.1 channel: podom) ! val: 0xc2100392a0 ok: true --==-=---=-=-=-==-
# OpenACMessage()
# [+] OpenACMessage: is podom a valid channel: false
# [+] OpenACMessage: not a channel, private conversation let's use this: podom=podom
# DECODE NONCE HEX(27): 706f646f6d3d706f646f6d3a706f646f6d3a030000003aa3baadb0 (podom=podom:podom:03000000:a3baadb0)
# AcprotoError[1]: OpenACMessage().SecretOpen(): false 


def privmsg_in_modifier_cb(data, modifier, modifier_data, msg_string):
    ret_string = msg_string
    myargs = {}
#    print "privmsg_in_modifier_cb():"
#    print "data: %s" % data
#    print "modifier: %s" % str(modifier)
#    print "modifier_data: %s" % str(modifier_data)
#    print "string: %s" % msg_string
#    print "MSG+STRING:"
#    print msg_string
    parsed = weechat.info_get_hashtable("irc_message_parse", { "message": msg_string, "server": modifier_data })
#    print "PARSED DICT"
#    print parsed
    if parsed.has_key(HPARSE_NICK) and parsed.has_key(HPARSE_HOST) and parsed.has_key(HPARSE_CHAN) and parsed.has_key(HPARSE_ARGS):
        peer_nick = parsed[HPARSE_NICK]
#        peer_host = parsed[HPARSE_HOST].split('!', 1)[1].strip()
        peer_host = parsed[HPARSE_HOST].split('!', 1).pop().strip()
        channel = parsed[HPARSE_CHAN]
        server = modifier_data
        peer_msg = parsed[HPARSE_ARGS].split(':',1)[1].strip()

        # XXX verify if the channel name is a nickname or a channel name, it is equivalent to if channel[0] != '#':
        retObj = re.match(acChannelRE, channel, re.M)
        if retObj == None:
#            print "MY MY NICK :"
            my_nick = channel
#            print my_nick
            channel = peer_nick
#            print "MY MY CHANNEL :"
#            print channel
#            print "PEER PEER NICK :"
#            print peer_nick
            myargs.update( { acwee.KEY_OPT:my_nick } )

        # XXX TODO: force to create buffer when there is none for a pk message received.. and display in that buffer..
        # XXX TODO: sanity checks!! error handling!!
        buffer = weechat.info_get("irc_buffer", "%s,%s" % (server, channel))
        inf = ac_get_buflocalinfo(buffer)

        # my nick..
        # my_nick = inf[BI_NICK]

        # XXX isAcEnabled ??
        # <ac> messages... need to strengthen the parsing/verification..
        if peer_msg.find(acCipherPrefix) == 0 and len(peer_msg) > len(acCipherPrefix)+1 and acwee.isAcActive(server, channel):
            msg_blob = peer_msg[len(acCipherPrefix):].strip()
            if ac_isb64(msg_blob) is False:
                acwee.pmbac(buffer, "Invalid message (b64) from %s [%s/%s]!", peer_nick, peer_nick, channel)
                return msg_string
            myargs.update({ acwee.KEY_PEERNICK:peer_nick, acwee.KEY_CHANNEL:channel, acwee.KEY_SERVER:server, acwee.KEY_BLOB:msg_blob })
            try:
                ac_ctr, err = acwee.acRequest(acwee.ACMSG_TYPE_CRYPTO, acwee.ACMSG_SUBTYPE_CTOPEN, myargs, acwee.BUF_LARGE)
            except Exception as e:
                acwee.pmbac(buffer, "!WARNING!\tMESSAGE NOT SENT: '%s' [NO ENCRYPTOR:%s]", out_msg, str(e))
            if ac_ctr and ac_ctr.bada == True:
                acwee.prtAcPrivMsg(buffer, peer_nick, ac_ctr.blob[0], "irc_privmsg,,notify_message,prefix_nick_default,nick_"+peer_nick+',host_'+peer_host)
#                weechat.prnt(buffer, "%s(%s%s%s)%s\t%s" % (weechat.color("white"), weechat.color("lightcyan"),peer_nick, weechat.color("white"), weechat.color("default"), ac_ctr.blob ))
                # SET NONCE / UPDATE happen in the callback, i hope it's not too slow...
                acwee.acUpdNonce(server, channel, ac_ctr.nonce)
                return ""
            else:
                #XXX TODO: check BUGS.txt... key check is not strong...
                acwee.pmb(buffer, "Invalid message from %s [%s/%s] %d (%s)!", peer_nick, peer_nick, channel, ac_ctr.error_code, err)

        # HOW TO DISPLAY PLAINTEXT
        if acwee.isAcEnabled(server, channel):
            return msg_string

        return msg_string

# XXX TODO: TO REMOVE this was an example/test
#def my_process_cb(data, command, return_code, out, err):
#    if return_code == weechat.WEECHAT_HOOK_PROCESS_ERROR:
#        weechat.prnt("", "Error with command '%s'" % command)
#        return weechat.WEECHAT_RC_OK
#    if return_code >= 0:
#        weechat.prnt("", "return_code = %d" % return_code)
#    if out != "":
#        weechat.prnt("", "stdout: %s" % out)
#    if err != "":
#        weechat.prnt("", "stderr: %s" % err)
#    return weechat.WEECHAT_RC_OK
#    
def ac_nonce_item_cb(data, item, window, buffer, extra_info):
    # KEY INFOS..
    inf = ac_get_buflocalinfo(buffer)
    nonce_val = acwee.acGetNonce(inf[BI_SERV], inf[BI_CHAN])
    if nonce_val != -1:
        nonce_str = "N: %08d" % nonce_val
    else:
        nonce_str = "N: N/A"
    return nonce_str 



#
#
#
#
#
#
# INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL
# INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL
# INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL
# INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL
# INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL
# INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL
#
# PROTOBUF CORE MESSAGE REQUESTS FUNCTIONS
#
# INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL
# INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL
# INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL
# INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL
# INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL
# INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL
#
#
#
#
#
#
#


class AcExceptions(Exception):
    acExceptions = None

    def __init__(self, **kwargs):
        print "our exception mechanism"
        # format { acName= acErrMsg= }
        self.acExceptions = kwargs

    def __str__(self):
        print repr(self.acExceptions)


class AcDisplay(object):
    AC_HDR = "AC"
    AC_COLOR = "yellow, blue"

    coreBuffer = None
    acHdrColor = None
    acHdr = None 
    acHdrMsg = None
    acBarColor = "red"
    acDebugLevel = 0
    acColorMyNick = weechat.color("red")
    acColorNick = weechat.color("green")
    acColorEnd = weechat.color("chat")

    def __init__(self, coreBuffer, acHdr = AC_HDR, hdrColor = AC_COLOR):
#        print "init our display"
        self.acHdrColor = weechat.color(hdrColor)
        self.acHdr = acHdr
        self.coreBuffer = coreBuffer
        self._buildAcHdr()

    def _buildAcHdr(self):
        self.acHdrMsg = "%s%s\t" % (self.acHdrColor, self.acHdr)

    def prtAcInfo(self, msg, *args):
        printMainMsg = msg % ( args )
        weechat.prnt(self.coreBuffer, "%s%s"% (self.acHdrMsg, printMainMsg)) 

    def setDebugLevel(self, level = 0):
        self.acDebugLevel = level

    def prtAcDbg(self, level, msg, *args):
        if self.acDebugLevel >= level:
            self.prtAcInfo(msg, args)

    def prtAcMsgBuf(self, buffer, fmt, *args):
#        print args
        printMainMsg = fmt % (args)
        weechat.prnt(buffer, "%s%s"% (self.acHdrMsg, printMainMsg)) 

    def pmbac(self, buffer, fmt, *args):
        prefixed = "** "+fmt
        self.prtAcMsgBuf(buffer, prefixed, *args)


    def pmb(self, buffer, fmt, *args):
        self.prtAcMsgBuf(buffer, fmt, *args)

    # XXX TODO type verification before printing..
    def prtAcPk(self, buffer, p, nick):
        # do i have the private key ?!
        if p.haspriv is True:
            self.pmb(buffer, "===>> %s%s!%s%s <<===" , self.acColorMyNick, p.nick, p.host, self.acColorEnd)
        else:
            self.pmb(buffer, "--->> %s%s!%s%s <<---", self.acColorNick, p.nick, p.host, self.acColorEnd)
    
        self.pmb(buffer, "\_ PK: %s", p.pubkey)
        self.pmb(buffer, "\_ FP: %s", binascii.hexlify(p.fp))
        self.pmb(buffer, "\_ Created: %s @ %s", str(datetime.datetime.fromtimestamp(p.timestamp)), p.server)

        return

    def prtAcPrivMsg(self, buffer, nick, message, tags):
#	weechat.print_date_tags(buffer)
	newtags = tags+',ACMSG'
	#weechat.prnt_date_tags(buffer, 0, newtags, message)
        #weechat.prnt(buffer, "%s(%s%s%s)%s\t%s" % (weechat.color("white"), weechat.color("lightcyan"), nick, weechat.color("white"), weechat.color("default"), message ))
        weechat.prnt_date_tags(buffer, 0, newtags, "%s(%s%s%s)%s\t%s" % (weechat.color("white"), weechat.color("lightcyan"), nick, weechat.color("white"), weechat.color("default"), message ))




class AcPbCom(object):
    # static defined variables

    # FOR PK Messages
    KEY_NICK    = 'nick'
    KEY_HOST    = 'host'
    KEY_SERVER  = 'serv'
    KEY_BLOB    = 'blob'

    # for KX Messages
    KEY_MYNICK      = 'mynick'
    KEY_PEERNICK    = 'peernick'
    KEY_CHANNEL     = 'chan'

    # for CT mMessages
    KEY_OPT = 'opt'

    # for CTL messages
    KEY_FILENAME = "filename"

    # the subtypes of public key msg generation
    ACMSG_SUBTYPE_PKGEN     = 0
    ACMSG_SUBTYPE_PKGET     = 1
    ACMSG_SUBTYPE_PKADD     = 2
    ACMSG_SUBTYPE_PKLIST    = 3
    ACMSG_SUBTYPE_PKDEL     = 4
    ACMSG_SUBTYPE_KXPACK    = 5
    ACMSG_SUBTYPE_KXUNPACK  = 6
    ACMSG_SUBTYPE_CTSEAL    = 7
    ACMSG_SUBTYPE_CTOPEN    = 8
    ACMSG_SUBTYPE_CTADD     = 9
    ACMSG_SUBTYPE_CTLPING   = 10
    ACMSG_SUBTYPE_CTLLOAD   = 11
    ACMSG_SUBTYPE_CTLSAVE   = 12

    # the message types / used for ac_msg() 
    ACMSG_TYPE_PK       = 0
    ACMSG_TYPE_KEX      = 1
    ACMSG_TYPE_CRYPTO   = 2
    ACMSG_TYPE_CTL      = 3
    ACMSG_TYPE_QUIT     = 4

    # depending on the type of data  we might need more space
    BUF_SMALL   = 2048
    BUF_LARGE   = 65536
    BUF_XXL     = 1048576

    # internal class variables
    # the subprocess class.
    acProc = None
    acBinary = None
    acDebugFile = None

    def __init__(self, acBin, acDbg):
        self.acBinary = [ acBin, "-debug=true" ]
        self.acDebugFile = acDbg
        self.acDebugFd = open(acDbg, 'w')

    def acStartDaemon(self):
# XXX TODO: handle the debugging channel correctly
        self.acProc = subprocess.Popen(self.acBinary, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.acDebugFd)
        flags = fcntl.fcntl(self.acProc.stdout, fcntl.F_GETFL) # get current p.stdout flags
        fcntl.fcntl(self.acProc.stdout, fcntl.F_SETFL, flags | os.O_NONBLOCK) # add non blocking 
        return None

    def acStopDaemon(self):
        self.acProc.terminate()
        # XXX TODO check return code to see if it's out.
        #self.acProc.returncode
        # XXX TODO that or terminate, let's go with terminate first..
#        acblob = self.acMsg(ACMSG_TYPE_QUIT, 0, None)
#        ac_pkr, err = self.acRequest(acblob, 0, BUF_LARGE)
#        ac_pkr, err = self.acRequest(self.ACMSG_TYPE_QUIT, 0, None, self.BUF_LARGE)
        return None

    def msgPkGen(self, args):
#        weechat.prnt("", "%sAC\tpkGEN args: " % ( weechat.color("yellow,blue") ) )
    #    print args
        acpkreq = ac_pb2.acPublicKeyMessageRequest()
        acpkreq.type = ac_pb2.acPublicKeyMessageRequest.PK_GEN
        acpkreq.nick = args[self.KEY_NICK] # mandatory
        acpkreq.server = args[self.KEY_SERVER] # mandatory
        acpkreq.host = args[self.KEY_HOST] # optional
        acpkreq.blob = args[self.KEY_BLOB] # optional
        return acpkreq.SerializeToString()

    def msgPkAdd(self, args):
#        print "pkADD args: "
#        print args
        acpkreq = ac_pb2.acPublicKeyMessageRequest()
        acpkreq.type = ac_pb2.acPublicKeyMessageRequest.PK_ADD
        acpkreq.nick = args[self.KEY_NICK] 
        acpkreq.server = args[self.KEY_SERVER] 
        acpkreq.host = args[self.KEY_HOST] 
        acpkreq.blob = args[self.KEY_BLOB] 
        return acpkreq.SerializeToString()

    def msgPkList(self, args):
    #    print "pkLIST args: "
    #    print args
        acpkreq = ac_pb2.acPublicKeyMessageRequest()
        acpkreq.type = ac_pb2.acPublicKeyMessageRequest.PK_LIST
        if args:
            if args.has_key(self.KEY_NICK):
#                print " I M HERE!!!"
                acpkreq.nick = args[self.KEY_NICK] 
            if args.has_key(self.KEY_SERVER):
                acpkreq.server = args[self.KEY_SERVER]
            else:
                print "NO SERVER GIVEN SO ERROR!"
        else:
            print "NO SERVER ARGS cascade error!"
        return acpkreq.SerializeToString()

    def msgPkDel(self, args):
#        print "pkDEL args: "
#        print args
        acpkreq = ac_pb2.acPublicKeyMessageRequest()
        acpkreq.type = ac_pb2.acPublicKeyMessageRequest.PK_DEL
        if args and args.has_key(self.KEY_NICK):
            acpkreq.nick = args[self.KEY_NICK] 
        if args.has_key(self.KEY_SERVER):
            acpkreq.server = args[self.KEY_SERVER] 
        return acpkreq.SerializeToString()


    def msgKxPack(self, args):
#        print "KXPACK args: "
#        print args
        ackxreq = ac_pb2.acKeyExchangeMessageRequest()
        ackxreq.type = ac_pb2.acKeyExchangeMessageRequest.KX_PACK
        if args and args.has_key(self.KEY_MYNICK):
            ackxreq.mynick = args[self.KEY_MYNICK]
        if args.has_key(self.KEY_PEERNICK):
            ackxreq.peernick = args[self.KEY_PEERNICK]
        if args.has_key(self.KEY_CHANNEL):
            ackxreq.channel = args[self.KEY_CHANNEL]
        if args.has_key(self.KEY_SERVER):
            ackxreq.server = args[self.KEY_SERVER]
        return ackxreq.SerializeToString()


    def msgKxUnpack(self, args):
#        print "KXUNPACK args: "
#        print args
        ackxreq = ac_pb2.acKeyExchangeMessageRequest()
        ackxreq.type = ac_pb2.acKeyExchangeMessageRequest.KX_UNPACK
        if args and args.has_key(self.KEY_MYNICK):
            ackxreq.mynick = args[self.KEY_MYNICK]
        if args.has_key(self.KEY_PEERNICK):
            ackxreq.peernick = args[self.KEY_PEERNICK]
        if args.has_key(self.KEY_CHANNEL):
            ackxreq.channel = args[self.KEY_CHANNEL]
        if args.has_key(self.KEY_SERVER):
            ackxreq.server = args[self.KEY_SERVER]
#        print "KEY_BLOB: "
#        print args[self.KEY_BLOB]
        if args[self.KEY_BLOB]:
            ackxreq.blob = args[self.KEY_BLOB]
    
        return ackxreq.SerializeToString()

    def msgCtSeal(self, args):
#        print "CTSEAL args: "
#        print args
    
        acctreq = ac_pb2.acCipherTextMessageRequest()
        acctreq.type = ac_pb2.acCipherTextMessageRequest.CT_SEAL
        if args and args.has_key(self.KEY_MYNICK):
            acctreq.nick = args[self.KEY_MYNICK]
        if args.has_key(self.KEY_BLOB):
            acctreq.blob = args[self.KEY_BLOB]
        if args.has_key(self.KEY_CHANNEL):
            acctreq.channel = args[self.KEY_CHANNEL]
        if args.has_key(self.KEY_SERVER):
            acctreq.server = args[self.KEY_SERVER]
        return acctreq.SerializeToString()

    def msgCtOpen(self, args):
#        print "CTOPEN args: "
#        print args
        acctreq = ac_pb2.acCipherTextMessageRequest()
        acctreq.type = ac_pb2.acCipherTextMessageRequest.CT_OPEN
        if args and args.has_key(self.KEY_PEERNICK):
            acctreq.nick = args[self.KEY_PEERNICK]
        if args.has_key(self.KEY_BLOB):
            acctreq.blob = args[self.KEY_BLOB]
        if args.has_key(self.KEY_CHANNEL):
            acctreq.channel = args[self.KEY_CHANNEL]
        if args.has_key(self.KEY_SERVER):
            acctreq.server = args[self.KEY_SERVER]
        if args.has_key(self.KEY_OPT):
            acctreq.opt = args[self.KEY_OPT]
        return acctreq.SerializeToString()

    def msgCtAdd(self, args):
        acctreq = ac_pb2.acCipherTextMessageRequest()
        acctreq.type = ac_pb2.acCipherTextMessageRequest.CT_ADD
        if args and args.has_key(self.KEY_NICK):
            acctreq.nick = args[self.KEY_NICK]
        if args.has_key(self.KEY_BLOB):
            acctreq.blob = args[self.KEY_BLOB]
        if args.has_key(self.KEY_CHANNEL):
            acctreq.channel = args[self.KEY_CHANNEL]
        if args.has_key(self.KEY_SERVER):
            acctreq.server = args[self.KEY_SERVER]
        return acctreq.SerializeToString()

    def msgCtlPing(self, args):
        acctreq = ac_pb2.acControlMessageRequest()
        acctreq.type = ac_pb2.acControlMessageRequest.CTL_PING
        # bleh
        return acctreq.SerializeToString()

    def msgCtlLoad(self, args):
        acctreq = ac_pb2.acControlMessageRequest()
        acctreq.filename = args[self.KEY_FILENAME]
        acctreq.type = ac_pb2.acControlMessageRequest.CTL_LOADCTX
        # bleh
        return acctreq.SerializeToString()

    def msgCtlSave(self, args):
        acctreq = ac_pb2.acControlMessageRequest()
        acctreq.filename = args[self.KEY_FILENAME]
        acctreq.type = ac_pb2.acControlMessageRequest.CTL_SAVECTX
        # bleh
        return acctreq.SerializeToString()

    def acPkMsg(self, subtype, args):
        if subtype == self.ACMSG_SUBTYPE_PKGEN:
            return self.msgPkGen(args)
        if subtype == self.ACMSG_SUBTYPE_PKADD:
            return self.msgPkAdd(args)
        if subtype == self.ACMSG_SUBTYPE_PKLIST:
            return self.msgPkList(args)
        if subtype == self.ACMSG_SUBTYPE_PKDEL:
            return self.msgPkDel(args)


    def acKexMsg(self, subtype, args):
        if subtype == self.ACMSG_SUBTYPE_KXPACK:
            return self.msgKxPack(args)
        if subtype == self.ACMSG_SUBTYPE_KXUNPACK:
            return self.msgKxUnpack(args)

    def acCryptoMsg(self, subtype, args):
        if subtype == self.ACMSG_SUBTYPE_CTSEAL:
            return self.msgCtSeal(args)
        if subtype == self.ACMSG_SUBTYPE_CTOPEN:
            return self.msgCtOpen(args)
        if subtype == self.ACMSG_SUBTYPE_CTADD:
            return self.msgCtAdd(args)

    def acControlMsg(self, subtype, args):
        if subtype == self.ACMSG_SUBTYPE_CTLPING:
            return self.msgCtlPing(args)
        if subtype == self.ACMSG_SUBTYPE_CTLLOAD:
            return self.msgCtlLoad(args)
        if subtype == self.ACMSG_SUBTYPE_CTLSAVE:
            return self.msgCtlSave(args)


    def acQuitMsg(self, subtype, args):
        print "QUIT subtype message builder."

    # build up the enveloppe 
    # XXX TODO: need error handling from the ac_pk_msg() and msg_pk* and similar functions...
    def _acMsg(self, type, subtype, args):
        acMsgObj = ac_pb2.ArseneCryptoMessage()

        if type == self.ACMSG_TYPE_PK:
            acMsgObj.type = ac_pb2.ArseneCryptoMessage.AC_PK
            acMsgObj.blob = self.acPkMsg(subtype, args)
        elif type == self.ACMSG_TYPE_KEX:
            acMsgObj.type = ac_pb2.ArseneCryptoMessage.AC_KEX
            acMsgObj.blob = self.acKexMsg(subtype, args)
        elif type == self.ACMSG_TYPE_CRYPTO:
            acMsgObj.type = ac_pb2.ArseneCryptoMessage.AC_CRYPTO
            acMsgObj.blob = self.acCryptoMsg(subtype, args)
        elif type == self.ACMSG_TYPE_CTL:
            acMsgObj.type = ac_pb2.ArseneCryptoMessage.AC_CTL
            acMsgObj.blob = self.acControlMsg(subtype, args)
        elif type == self.ACMSG_TYPE_QUIT:
            acMsgObj.type = ac_pb2.ArseneCryptoMessage.AC_QUIT
            acMsgObj.blob = "" #ac_quit_msg(subtype, args)
        else:
            print "invalid message build"

        ret_blob = acMsgObj.SerializeToString()
        return ret_blob


    # return [ Blob|None, Error|None ]
    def _acRequest(self, reqblob, actype, bufsize):
        # XXX TODO retransmit mechanism..
        self.acProc.stdin.write(reqblob)
        # XXX TODO: this is a hack need a proper select loop here.. :)
        # also let's poll stderr to get errors and display it in a status window..
        #time.sleep(0.1)
        rlist, wlist, xlist = select.select([self.acProc.stdout], [], [], 1)
        if (rlist):
            rcvBlob = self.acProc.stdout.read(bufsize)
        else:
            # XXX TODO: need to message the process back
            print "PROCESS COMMUNICATION TIMEOUT!!!"
            print "RLIST"
            print rlist
            print "WLIST"
            print wlist
            print "XLIST"
            print xlist
            return [ None, "No Read List Polled" ]
    
        # XXX TODO: surround with try/except
        acRcvEnvp = ac_pb2.ArseneCryptoMessage()
        acRcvEnvp.ParseFromString(rcvBlob)
    
        if acRcvEnvp.type == ac_pb2.ArseneCryptoMessage.AC_PK and actype == self.ACMSG_TYPE_PK:
            acResponse = ac_pb2.acPublicKeyMessageResponse()
        elif acRcvEnvp.type == ac_pb2.ArseneCryptoMessage.AC_KEX and actype == self.ACMSG_TYPE_KEX:
            acResponse = ac_pb2.acKeyExchangeMessageResponse()
        elif acRcvEnvp.type == ac_pb2.ArseneCryptoMessage.AC_CRYPTO and actype == self.ACMSG_TYPE_CRYPTO:
            acResponse = ac_pb2.acCipherTextMessageResponse()
        # XXX TODO: error to should be handled..
        elif acRcvEnvp.type == ac_pb2.ArseneCryptoMessage.AC_ERROR:
            return [ None, acRcvEnvp.blob ] # AC_ERROR, I should have the message, don't know if it's nice this way..
        else:
            return [ None, "Unknown Error" ] # Unknown error

        # XXX TODO: surround in try/except
        acResponse.ParseFromString(acRcvEnvp.blob)
        return [ acResponse, None ]

    def acRequest(self, type, subtype, args, bufsize = BUF_SMALL): 
        acblob = self._acMsg(type, subtype, args)
#        ac_pkr, err = self._acRequest(acblob, type=type, bufsize=bufsize)
        return self._acRequest(acblob, type, bufsize)




# XXX TODO: now the main class the AcCore class which will embed all that is
# necessary to make the script run smoothly and communicate with the stdin/stdou
# go binary daemon..

class AcCore(AcDisplay, AcPbCom):
    acCipherReady = {} # sha1 hash 'channel:server'
    acCipherBar = {} # sha1 hash 'channel:server' store the bar display pointer.
    acCipherDesc = {} # sha1 hash ' channel:server' information to display
    acRecvKeyBlobs = {} # sha1 hash 'channel:server'
    acNonces = {} # sha1 hash 'channel:server' store bar items value for now.
    acBarItems = []

    A_title = [ "Arrivist", "Afghan", "Alternate", "Achille", "Archivist", "Aborted", "Applied", "Armani", "Asynchronous", "Armenian", "American", "Advanced", "Acrobatic" ]
    S_title = [ "System", "Sodomist", "Sudoku", "Subculture", "Slider", "Sledge", "Shit", "Shoarma", "Shuriken", "Sheeva", "Sonia", "Sucker" ]

    def __init__(self, coreBuffer, acBinFile, acDbgFile):
        AcDisplay.__init__(self, "")
        AcPbCom.__init__(self, acBinFile, acDbgFile)
        self.acCipherReady = {}
        self.acCipherBar = {}
        self.acCipherDesc = {}
        self.acRecvKeyBlobs = {}
        self.acNonces = {}
        self.BarItems = []

    def acBanner(self, buffer):
#        buffer = weechat.current_buffer();
        self.pmb(buffer, "$#%%$#@%%#%%@#$%%@#$%%@$#%%@#$%%@#$%%@#$%%@#$%%#@$%%#@$%%@#$%%@#%%@#$%%@")
        self.pmb(buffer, "%s Crypto %s %s (c) 2013-2014 Security Gigolos ", random.choice(self.A_title), random.choice(self.S_title), SCRIPT_VERSION)
        self.pmb(buffer, "by %s", SCRIPT_AUTHOR)
        self.pmb(buffer, "Implements AEAD: NaCL/ECC Curve 25519 w/ Salsa20/Poly1305 (more later)")
        self.pmb(buffer, "type: /ac help to get HELP!")
        self.pmb(buffer, "$#%%$#@%%#%%@#$%%@#$%%@$#%%@#$%%@#$%%@#$%%@#$%%#@$%%#@$%%@#$%%@#%%@#$%%@")

    def _buildHash(self, serv, chan):
        return hashlib.sha1(chan+":"+serv).hexdigest()

    def coreCleanUp(self):
        for keyHash in self.acCipherReady:
            self.acCipherReady[keyHash] = False
#            del self.acCipherReady[keyHash]
        for keyHash in self.acCipherBar:
            weechat.bar_remove(self.acCipherBar[keyHash])
#            del self.acCipherBar[keyHash]
#        for keyHash in self.acCipherDesc:
#            del self.acCipherDesc[keyHash]
        self.acCipherReady = {}
        self.acCipherDesc = {}
        self.acCipherBar = {}
        self.acRecvKeyBlobs = {}
    
    def rcvKexPush(self, serv, chan, kexDataList):
        keyBlobHash = self._buildHash(serv, chan)
        self.acRecvKeyBlobs[keyBlobHash] = kexDataList

    def rcvKexPop(self, serv, chan):
        keyBlobHash = self._buildHash(serv, chan)
        if self.acRecvKeyBlobs.has_key(keyBlobHash):
            kexDataList = self.acRecvKeyBlobs[keyBlobHash]
            del self.acRecvKeyBlobs[keyBlobHash]
            return kexDataList
        else:
            return None
    def isAcEnabled(self, serv, chan):
        keyBlobHash = self._buildHash(serv, chan)
        if self.acCipherReady.has_key(keyBlobHash) and self.acCipherReady[keyBlobHash] == True:
            return True
        else:
            return False

    def isAcActive(self, serv, chan):
        keyBlobHash = self._buildHash(serv, chan)
        if self.acCipherReady.has_key(keyBlobHash):
            return True
        else:
            return False

    def acEnable(self, buffer, serv, chan):
        keyBlobHash = self._buildHash(serv, chan)
        keyBlobDescList = [serv, chan]
        self.acCipherDesc[keyBlobHash] = keyBlobDescList
        return self.acEnableHash(buffer, keyBlobHash)

    def acDisable(self, buffer, serv, chan):
        keyBlobHash = self._buildHash(serv, chan)
        return self.acDisableHash(buffer, keyBlobHash)

    def acSetNonce(self, serv, chan, nonce):
        keyBlobHash = self._buildHash(serv, chan)
        self.acNonces[keyBlobHash] = nonce

    def acUpdNonce(self, serv, chan, nonce):
        self.acSetNonce(serv, chan, nonce)
        weechat.bar_item_update("ac_nonce")

    def acGetNonce(self, serv, chan):
        keyBlobHash = self._buildHash(serv, chan)
        if self.acNonces.has_key(keyBlobHash):
            return self.acNonces[keyBlobHash]
        else:
            return -1


    # TODO XXX bar color, bar items messages in AcDisplay class to avoid
    # rewriting it... AcDisplay should create the bar items we can use to
    # display more information regarding the number of messages sent with 
    # the current key.
    def acEnableHash(self, buffer, keyBlobHash):
        self.pmb(buffer, "encryption enabled")
        # get the buffer name and display only in that buffer...
        bufname = weechat.buffer_get_string(buffer, "full_name")
        bar_condition = "${buffer.full_name} == %s" % bufname
        self.acCipherReady[keyBlobHash] = True
        if self.acCipherBar.has_key(keyBlobHash) is False:
            cipher_bar = weechat.bar_new(keyBlobHash, "off", "400", "window", bar_condition, "bottom", "horizontal", "vertical", "0", "5", "default", "cyan", "red", "off", ":::::: buffer_name, ac_nonce ::::::")
            self.acCipherBar[keyBlobHash] = cipher_bar
        return weechat.WEECHAT_RC_OK
    
    def acDisableHash(self, buffer, keyBlobHash):
        self.pmb(buffer, "encryption disabled")
        self.acCipherReady[keyBlobHash] = False
        cipher_bar = self.acCipherBar[keyBlobHash]
        weechat.bar_remove(cipher_bar)
        del self.acCipherBar[keyBlobHash]
        return weechat.WEECHAT_RC_OK

    # XXX TOREMOVE
    def acHashList(self, dabuffer):
        self.pmb(dabuffer, "= CHANs =")
        for keyHash in self.acCipherReady:
            descList = self.acCipherDesc[keyHash]
            self.pmb(dabuffer, "%s/%s [%s] -> %r", descList[0], descList[1], keyHash, self.acCipherReady[keyHash])
        self.pmb(dabuffer, "= BARs =")
        for keyHash in self.acCipherBar:
            descList = self.acCipherDesc[keyHash]
            self.pmb(dabuffer, "%s/%s [%s] -> %r", descList[0], descList[1], keyHash, self.acCipherBar[keyHash])


    
#
# AcWeechat related stuff, like hooking mechanism, heartbeat, etc...
# and get all from AcCore, communication, display, etc..
# 
class AcWeechat(AcCore):
    CMD_HKEY_NAME = "name"
    CMD_HKEY_CB = "cb"

    CMD_PUBKEY  = { CMD_HKEY_NAME:"pk",     CMD_HKEY_CB: "pkCmd_CB" }
    CMD_SNDKEY  = { CMD_HKEY_NAME:"sk",     CMD_HKEY_CB: "skCmd_CB" }
    CMD_ACCMD   = { CMD_HKEY_NAME:"ac",     CMD_HKEY_CB: "acCmd_CB" }

    def __init__(self, acBin, acDbg):
        AcCore.__init__(self, "", acBin, acDbg)
#
#
# Hooks
#
#
    def acCmdHooks(self):
#        weechat.hook_command(self.CMD_HELP[self.CMD_HKEY_NAME], "AC help command", "", "", "", self.CMD_HELP[self.CMD_HKEY_CB], "")
        weechat.hook_command(self.CMD_PUBKEY[self.CMD_HKEY_NAME], "/pk help for more infos", "", "", "", self.CMD_PUBKEY[self.CMD_HKEY_CB], "")
        weechat.hook_command(self.CMD_SNDKEY[self.CMD_HKEY_NAME], "/sk help for more infos", "", "", "nick", self.CMD_SNDKEY[self.CMD_HKEY_CB], "")
        weechat.hook_command(self.CMD_ACCMD[self.CMD_HKEY_NAME], "enable/disable encryption on the current buffer", "", "", "", self.CMD_ACCMD[self.CMD_HKEY_CB], "")
        return weechat.WEECHAT_RC_OK

    def acTimerHooks(self):
    #    weechat.hook_timer(1000, 0, 0, "ac_checktimer_cb", "prout")
        return weechat.WEECHAT_RC_OK

    def acSignalHooks(self):
    #    weechat.hook_signal("*,irc_in_notice", "notice_in_signal_cb", "")
    #    weechat.hook_signal("*,irc_in2_notice", "notice_in_signal_cb", "")
        return weechat.WEECHAT_RC_OK

    # this is what we get...
    #: stdout/stderr: string: croute | <acpk> qDtHEHjaOnn41qNtJqKuq1r7l0W9PyWk+fvP5Y3i5olWqhdc9sc62gMCAAD//yrCEHg=
    #: stdout/stderr: data: proutprout
    #: stdout/stderr: modifier: weechat_print
    #: stdout/stderr: modifier_data: irc;freenode.#crutcruton;irc_privmsg,notify_message,prefix_nick_default,nick_croute,log1
    #
    def acModifierHooks(self):
        # input message hooks
        weechat.hook_modifier("weechat_print", "printmsg_modifier_cb", "")
        weechat.hook_modifier("irc_in_notice", "notice_in_modifier_cb", "")
        weechat.hook_modifier("irc_in_privmsg", "privmsg_in_modifier_cb", "")
        weechat.hook_modifier("irc_out_privmsg", "privmsg_out_modifier_cb", "")
        return weechat.WEECHAT_RC_OK

    def acHooks(self):
        self.acSignalHooks()
        self.acModifierHooks()
        self.acCmdHooks()
        self.acTimerHooks()
#    acProcessHooks()
#    weechat.hook_command("achelp", "AC help command",
#            "[pubkey]|[givekey name]|[list [name|nick]]",
#            "arg description",
#            "pubkey"
#            "||givekey name|nick"
#            "||list nick|*",
#            "achelp_cb",
#            "")
        return weechat.WEECHAT_RC_OK

    def acUnHooks(self):
        weechat.unhook_all()

    def acEnvInit(self):
        # here we will enable environnement, config variables
        # and setup the bar items we need for display
        bar_item = weechat.bar_item_new("(extra)ac_nonce", "ac_nonce_item_cb", "")
        return None

    #
    #
    #
    #
    #
    # MAIN FUNCTION
    #
    #
    #
    #
    #
    def acWeechatError(self):
        self.pmb(weechat.current_buffer(), "Bye, you got errors!")
    
    def acWeechatMain(self):
    #    weechat.prnt("", "Hello, from python script!")
    #    weechat.prnt("", "%sDSALDSAKDLASg arguments" % weechat.prefix("error"))
    #    weechat.prnt("", "%swrong arguments" % weechat.prefix(""))
    #    weechat.prnt("", "%sAC\twrong arguments" % weechat.color("yellow,blue"))
    #    weechat.config_set_plugin("look.prefix_ac", "AC")
    #    weechat.prnt("", "text %syellow on blue" % weechat.color("yellow,blue"))
    #   OLD
    #   ac_startup()
    #   NEW
        self.acBanner( weechat.current_buffer() )
        self.acStartDaemon()
        self.acEnvInit()
        self.acHooks()
    
    def acWeechatExit(self):
        self.coreCleanUp()
        self.acStopDaemon()
        self.acUnHooks()
        self.pmb(self.coreBuffer, "$#%%$#@%%#%%@#$%%@#$%%@$#%%@#$%% ac OUT! @#$%%@#$%%@#$%%#@$%%#@$%%@#$%%@#%%@#$%%@")
        return weechat.WEECHAT_RC_OK


#
#
#
# END OF INTERNALS PROTOBUF FUNCTIONS
#
#
# INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL
# INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL
# INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL
# INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL
# INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL
# INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL
#
# PROTOBUF CORE MESSAGE REQUESTS FUNCTIONS
#
# INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL
# INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL
# INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL
# INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL
# INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL
# INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL INTERNAL
#

# a hack as weechat cannot call class function of an instanciated class
def acWeechatExit():
    return acwee.acWeechatExit()

# we register the script now
if __name__ == "__main__":
    # registering our global object
    acwee = AcWeechat(AC_BINARY, AC_DEBUGFILE)
    if weechat.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION, SCRIPT_LICENSE, SCRIPT_DESC, "acWeechatExit", ""):
        acwee.acWeechatMain()
    else:
        acwee.acWeechatError()

