#!/opt/local/bin/python2.7
#
#
# this is the protocol client test tool
# it will also serve to see implementation details from 
# the weechat plugin, which will be implemented in py
#
# I really hope i'm doing things cleanly...
# 
import ac_pb2
import os
import socket
import sys
import time
import datetime
import binascii

# TYPE
# Public Key = 0
#  sub type:
#  PK_GEN = 0 { nick: }
#  PK_GET = 1
#  PK_ADD = 2
#  PK_LIST = 3
#  PK_DEL = 4

# Key Exchange = 1
#  sub type:
#  TBD

# Crypt Message = 2
#  sub type:
#  TBD

# PING msg = 3
#  no subtype.

# FOR PK Messages
KEY_NICK = 'nick'
KEY_HOST = 'host'
KEY_SERVER = 'serv'
KEY_BLOB = 'blob'

KEY_HOST_DATA = 'eau@uri.com'
KEY_YAHOST_DATA = 'zobby@uri.com'
KEY_SERVER_DATA = 'irc.freenode.net'

DATA_BLOB = ""

# for KX Messages
KEY_MYNICK = 'mynick'
KEY_PEERNICK = 'peernick'
KEY_CHANNEL = 'chan'

def msg_pkgen(args):
    print "pkGEN args: "
    print args
    acpkreq = ac_pb2.acPublicKeyMessageRequest()
    acpkreq.type = ac_pb2.acPublicKeyMessageRequest.PK_GEN
    acpkreq.nick = args[KEY_NICK] 
    acpkreq.host = args[KEY_HOST] 
    acpkreq.server = args[KEY_SERVER] 
    acpkreq.blob = args[KEY_BLOB] 
    return acpkreq.SerializeToString()


def msg_pkget(args):
    print "pkGET args: "
    print args
    acpkreq = ac_pb2.acPublicKeyMessageRequest()
    acpkreq.type = ac_pb2.acPublicKeyMessageRequest.PK_GET
    acpkreq.nick = args[KEY_NICK] 
    return acpkreq.SerializeToString()

def msg_pkadd(args):
    print "pkADD args: "
    print args
    acpkreq = ac_pb2.acPublicKeyMessageRequest()
    acpkreq.type = ac_pb2.acPublicKeyMessageRequest.PK_ADD
    acpkreq.nick = args[KEY_NICK] 
    acpkreq.host = args[KEY_HOST] 
    acpkreq.server = args[KEY_SERVER] 
    acpkreq.blob = args[KEY_BLOB] 
    return acpkreq.SerializeToString()

def msg_pklist(args):
    print "pkLIST args: "
    print args
    acpkreq = ac_pb2.acPublicKeyMessageRequest()
    acpkreq.type = ac_pb2.acPublicKeyMessageRequest.PK_LIST
    if args and args[KEY_NICK]:
        print " I M HERE!!!"
        acpkreq.nick = args[KEY_NICK] 
    return acpkreq.SerializeToString()

def msg_pkdel(args):
    print "pkDEL args: "
    print args
    acpkreq = ac_pb2.acPublicKeyMessageRequest()
    acpkreq.type = ac_pb2.acPublicKeyMessageRequest.PK_DEL
    if args and args[KEY_NICK]:
        acpkreq.nick = args[KEY_NICK] 
    return acpkreq.SerializeToString()


def msg_kxpack(args):
    print "KXPACK args: "
    print args
    ackxreq = ac_pb2.acKeyExchangeMessageRequest()
    ackxreq.type = ac_pb2.acKeyExchangeMessageRequest.KX_PACK
    if args and args[KEY_MYNICK]:
        ackxreq.mynick = args[KEY_MYNICK]
    if args[KEY_PEERNICK]:
        ackxreq.peernick = args[KEY_PEERNICK]
    if args[KEY_CHANNEL]:
        ackxreq.channel = args[KEY_CHANNEL]
    return ackxreq.SerializeToString()

def msg_kxunpack(args):
    print "KXUNPACK args: "
    print args
    ackxreq = ac_pb2.acKeyExchangeMessageRequest()
    ackxreq.type = ac_pb2.acKeyExchangeMessageRequest.KX_UNPACK
    if args and args[KEY_MYNICK]:
        ackxreq.mynick = args[KEY_MYNICK]
    if args[KEY_PEERNICK]:
        ackxreq.peernick = args[KEY_PEERNICK]
    if args[KEY_CHANNEL]:
        ackxreq.channel = args[KEY_CHANNEL]
    print "KEY_BLOB: "
    print args[KEY_BLOB]
    if args[KEY_BLOB]:
        ackxreq.blob = args[KEY_BLOB]

    return ackxreq.SerializeToString()


def msg_ctseal(args):
    print "CTSEAL args: "
    print args

    acctreq = ac_pb2.acCipherTextMessageRequest()
    acctreq.type = ac_pb2.acCipherTextMessageRequest.CT_SEAL
    if args and args[KEY_MYNICK]:
        acctreq.nick = args[KEY_MYNICK]
    if args[KEY_BLOB]:
        acctreq.blob = args[KEY_BLOB]
    if args[KEY_CHANNEL]:
        acctreq.channel = args[KEY_CHANNEL]
    return acctreq.SerializeToString()

def msg_ctopen(args):
    print "CTOPEN args: "
    print args

    acctreq = ac_pb2.acCipherTextMessageRequest()
    acctreq.type = ac_pb2.acCipherTextMessageRequest.CT_OPEN
    if args and args[KEY_PEERNICK]:
        acctreq.nick = args[KEY_PEERNICK]
    if args[KEY_BLOB]:
        acctreq.blob = args[KEY_BLOB]
    if args[KEY_CHANNEL]:
        acctreq.channel = args[KEY_CHANNEL]
    return acctreq.SerializeToString()


# the subtypes of public key msg generation
ACMSG_SUBTYPE_PKGEN = 0
ACMSG_SUBTYPE_PKGET = 1
ACMSG_SUBTYPE_PKADD = 2
ACMSG_SUBTYPE_PKLIST = 3
ACMSG_SUBTYPE_PKDEL = 4
ACMSG_SUBTYPE_KXPACK = 5
ACMSG_SUBTYPE_KXUNPACK = 6
ACMSG_SUBTYPE_CTSEAL = 7
ACMSG_SUBTYPE_CTOPEN = 8

def ac_pk_msg(subtype, args):
    print "PK subtype message builder."
    if subtype == ACMSG_SUBTYPE_PKGEN:
        print "PK GEN message"
        return msg_pkgen(args)
    if subtype == ACMSG_SUBTYPE_PKGET:
        print "PK GET message"
        return msg_pkget(args)
    if subtype == ACMSG_SUBTYPE_PKADD:
        print "PK ADD message"
        return msg_pkadd(args)
    if subtype == ACMSG_SUBTYPE_PKLIST:
        print "PK LIST message"
        return msg_pklist(args)
    if subtype == ACMSG_SUBTYPE_PKDEL:
        print "PK DEL message"
        return msg_pkdel(args)


def ac_kex_msg(subtype, args):
    print "KEX subtype message builder."
    if subtype == ACMSG_SUBTYPE_KXPACK:
        print "KXPACK Message"
        return msg_kxpack(args)
    if subtype == ACMSG_SUBTYPE_KXUNPACK:
        print "KXPACK Message"
        return msg_kxunpack(args)

def ac_crypto_msg(subtype, args):
    print "CRYPT subtype message builder."
    if subtype == ACMSG_SUBTYPE_CTSEAL:
        print "CTSEAL Message"
        return msg_ctseal(args)
    if subtype == ACMSG_SUBTYPE_CTOPEN:
        print "CTOPEN Message"
        return msg_ctopen(args)

def ac_ping_msg(subtype, args):
    print "PING subtype message builder."

# test generate full exchange messages..
ACMSG_TYPE_PK = 0
ACMSG_TYPE_KEX = 1
ACMSG_TYPE_CRYPTO = 2
ACMSG_TYPE_PING = 3

def ac_msg(type = ACMSG_TYPE_PK, subtype = ACMSG_SUBTYPE_PKGEN, args = None):
    acmsg = ac_pb2.ArseneCryptoMessage()

    if type == ACMSG_TYPE_PK:
        acmsg.type = ac_pb2.ArseneCryptoMessage.AC_PK
        acmsg.blob = ac_pk_msg(subtype, args)
    elif type == ACMSG_TYPE_KEX:
        acmsg.type = ac_pb2.ArseneCryptoMessage.AC_KEX
        acmsg.blob = ac_kex_msg(subtype, args)
    elif type == ACMSG_TYPE_CRYPTO:
        acmsg.type = ac_pb2.ArseneCryptoMessage.AC_CRYPTO
        acmsg.blob = ac_crypto_msg(subtype, args)
    elif type == ACMSG_TYPE_PING:
        ac_ping_msg(subtype, args)
    else:
        print "invalid message build"

    ret_blob = acmsg.SerializeToString()
    return ret_blob



######## LITTLE TEST FUNCTIONS ###########
def pk_getnewpair(sfd):
#
#   GET NEW KEYPAIR MESSAGE
# 
    print "GENERATE NEW KEYPAIR MESSAGE"

    #myargs = { KEY_NICK:"yondaime", KEY_HOST:KEY_HOST_DATA, KEY_SERVER:KEY_SERVER_DATA, KEY_BLOB:"ddskjdkdjsakjdasksa" }
    myargs = { KEY_NICK:"yondaime", KEY_HOST:KEY_HOST_DATA, KEY_SERVER:"", KEY_BLOB:"ddskjdkdjsakjdasksa" }
    acblob = ac_msg(ACMSG_TYPE_PK, ACMSG_SUBTYPE_PKGEN, myargs)

    sfd.send(acblob)
    rcvblob = sfd.recv(2048)

    ac_msg_test = ac_pb2.ArseneCryptoMessage()
    ac_msg_test.ParseFromString(rcvblob)
    print "message type:"
    print ac_msg_test.type

    ac_pkr = ac_pb2.acPublicKeyMessageResponse()
    ac_pkr.ParseFromString(ac_msg_test.blob)
    print "PKR message type:"
    print ac_pkr.type
    print "PKR message bada:"
    print ac_pkr.bada
    print "PKR message error_code:"
    print "%d" % ac_pkr.error_code
    return 0


# TODO we can simplify the protocol by relying only on PK_LIST and providing '@' as nickname to get
# to simplify the protocol.. and to get my own key information...
def pk_getmypubkey(sfd):
    print "GET MY PUBLIC KEY"
    myargs = { KEY_NICK:"youpiya" }
    acblob = ac_msg(ACMSG_TYPE_PK, ACMSG_SUBTYPE_PKGET, myargs)
    sfd.send(acblob)
    rcvblob = sfd.recv(2048)

    ac_msg_test = ac_pb2.ArseneCryptoMessage()
    ac_msg_test.ParseFromString(rcvblob)
    print "message type:"
    print ac_msg_test.type

    ac_pkr = ac_pb2.acPublicKeyMessageResponse()
    ac_pkr.ParseFromString(ac_msg_test.blob)
    print "PKR message type:"
    print ac_pkr.type
    print "PKR message bada:"
    print ac_pkr.bada
    print "PKR message error_code:"
    print ac_pkr.error_code
    print "PKR do we have public keys?!"
    print ac_pkr.public_keys
    print "HOW MANY PUB KEYS!?"
    print len(ac_pkr.public_keys)
    for t in ac_pkr.public_keys:
        print t.nick + ":" + t.pubkey + ":" + str(t.timestamp) + ":" + str(datetime.datetime.fromtimestamp(t.timestamp))
        print binascii.hexlify(t.fp)
    return 0


def pk_addpubkey(sfd):
    print "ADD A PUBKEY"
    myargs = { KEY_NICK:"frlfrl", KEY_HOST:KEY_YAHOST_DATA, KEY_SERVER:KEY_SERVER_DATA, KEY_BLOB:"IpPlkHjaehHIva58t9UOk92x3HIa9mzG9wWzt8i/Tlpzpj/W64+iNiAAAP//3ukNnQ==" }
    acblob = ac_msg(ACMSG_TYPE_PK, ACMSG_SUBTYPE_PKADD, myargs)
    sfd.send(acblob)
    rcvblob = sfd.recv(2048)

    ac_msg_test = ac_pb2.ArseneCryptoMessage()
    ac_msg_test.ParseFromString(rcvblob)
    print "message type:"
    print ac_msg_test.type

    ac_pkr = ac_pb2.acPublicKeyMessageResponse()
    ac_pkr.ParseFromString(ac_msg_test.blob)
    print "PKR message type:"
    print ac_pkr.type
    print "PKR message bada:"
    print ac_pkr.bada
    print "PKR message error_code:"
    print ac_pkr.error_code
    print "KEY FP:"
    print binascii.hexlify(ac_pkr.blob)

def pk_list(sfd):
    print "LIST RUNNING DAEMON PUBLIC KEYS"
    #myargs = { KEY_NICK:"frlfrl" }
    myargs = None 
    acblob = ac_msg(ACMSG_TYPE_PK, ACMSG_SUBTYPE_PKLIST, myargs)
    sfd.send(acblob)
    rcvblob = sfd.recv(4096)

    ac_msg_test = ac_pb2.ArseneCryptoMessage()
    ac_msg_test.ParseFromString(rcvblob)
    print "message type:"
    print ac_msg_test.type

    if ac_msg_test.type == ac_pb2.ArseneCryptoMessage.AC_ERROR:
        print "Request Error!"
        print ac_msg_test.blob
        return 1
    ac_pkr = ac_pb2.acPublicKeyMessageResponse()
    ac_pkr.ParseFromString(ac_msg_test.blob)
    print "PKR message type:"
    print ac_pkr.type
    print "PKR message bada:"
    print ac_pkr.bada
    print "PKR message error_code:"
    print ac_pkr.error_code
    print "PKR do we have public keys?!"
    print ac_pkr.public_keys
    print "HOW MANY PUB KEYS!?"
    print len(ac_pkr.public_keys)
    for t in ac_pkr.public_keys:
        print t.nick + ":" + t.pubkey + ":" + str(t.timestamp) + ":" + str(datetime.datetime.fromtimestamp(t.timestamp))
        print binascii.hexlify(t.fp)
    return 0

def pk_del(sfd):
    print "DEL message"
    #myargs = { KEY_NICK:"frlfrl" }
    myargs = None # { KEY_NICK:"frlfrl" }

    acblob = ac_msg(ACMSG_TYPE_PK, ACMSG_SUBTYPE_PKDEL, myargs)
    sfd.send(acblob)
    rcvblob = sfd.recv(4096)

    ac_msg_test = ac_pb2.ArseneCryptoMessage()
    ac_msg_test.ParseFromString(rcvblob)
    print "message type:"
    print ac_msg_test.type

    ac_pkr = ac_pb2.acPublicKeyMessageResponse()
    ac_pkr.ParseFromString(ac_msg_test.blob)
    print "PKR message type:"
    print ac_pkr.type
    print "PKR message bada:"
    print ac_pkr.bada
    print "PKR message error_code:"
    print ac_pkr.error_code


def kx_sendkey(sfd):
    print "KXPACK message"
    myargs = { KEY_MYNICK:"yondaime", KEY_PEERNICK:"frlfrl", KEY_CHANNEL:"#prout" }

    acblob = ac_msg(ACMSG_TYPE_KEX, ACMSG_SUBTYPE_KXPACK, myargs)
    sfd.send(acblob)
    rcvblob = sfd.recv(4096)

    ac_msg_test = ac_pb2.ArseneCryptoMessage()
    ac_msg_test.ParseFromString(rcvblob)
    print "message type:"
    print ac_msg_test.type

    ac_kxr = ac_pb2.acKeyExchangeMessageResponse()
    ac_kxr.ParseFromString(ac_msg_test.blob)
    print "KXR message type:"
    print ac_kxr.type
    print "KXR message bada:"
    print ac_kxr.bada
    print "KXR message error_code:"
    print ac_kxr.error_code
    print "KXR message blob:"
    print ac_kxr.blob
    DATA_BLOB = ac_kxr.blob
    print "DATABLOB"
    print DATA_BLOB
    return DATA_BLOB


def kx_recvkey(sfd):
    print "KXUNPACK message: " + DATA_BLOB
    myargs = { KEY_MYNICK:"frlfrl", KEY_PEERNICK:"yondaime", KEY_CHANNEL:"#prout", KEY_BLOB:DATA_BLOB }

    acblob = ac_msg(ACMSG_TYPE_KEX, ACMSG_SUBTYPE_KXUNPACK, myargs)
    sfd.send(acblob)
    rcvblob = sfd.recv(4096)

    ac_msg_test = ac_pb2.ArseneCryptoMessage()
    ac_msg_test.ParseFromString(rcvblob)
    print "message type:"
    print ac_msg_test.type

    ac_kxr = ac_pb2.acKeyExchangeMessageResponse()
    ac_kxr.ParseFromString(ac_msg_test.blob)
    print "KXR message type:"
    print ac_kxr.type
    print "KXR message bada:"
    print ac_kxr.bada
    print "KXR message error_code:"
    print ac_kxr.error_code

def ct_seal(sfd):
    print "CTSEAL message: " 
    myargs = { KEY_MYNICK:"frlfrl", KEY_BLOB:"this is a message to say yay!!!!", KEY_CHANNEL:"#prout" }

    acblob = ac_msg(ACMSG_TYPE_CRYPTO, ACMSG_SUBTYPE_CTSEAL, myargs)
    sfd.send(acblob)
    rcvblob = sfd.recv(4096)

    ac_msg_test = ac_pb2.ArseneCryptoMessage()
    ac_msg_test.ParseFromString(rcvblob)
    print "message type:"
    print ac_msg_test.type

    ac_ctr = ac_pb2.acCipherTextMessageResponse()
    ac_ctr.ParseFromString(ac_msg_test.blob)
    print "CTR message type:"
    print ac_ctr.type
    print "CTR message bada:"
    print ac_ctr.bada
    print "CTR message error_code:"
    print ac_ctr.error_code
    print "CTR message blob:"
    print ac_ctr.blob

    return ac_ctr.blob

def ct_open(sfd):
    print "CTOPEN message: " 
    myargs = { KEY_PEERNICK:"rlfrl", KEY_BLOB:DATA_BLOB, KEY_CHANNEL:"#prout" }

    acblob = ac_msg(ACMSG_TYPE_CRYPTO, ACMSG_SUBTYPE_CTOPEN, myargs)
    sfd.send(acblob)
    rcvblob = sfd.recv(4096)

    ac_msg_test = ac_pb2.ArseneCryptoMessage()
    ac_msg_test.ParseFromString(rcvblob)
    print "message type:"
    print ac_msg_test.type

    ac_ctr = ac_pb2.acCipherTextMessageResponse()
    ac_ctr.ParseFromString(ac_msg_test.blob)
    print "CTR message type:"
    print ac_ctr.type
    print "CTR message bada:"
    print ac_ctr.bada
    print "CTR message error_code:"
    print ac_ctr.error_code
    print "CTR message blob:"
    print ac_ctr.blob

    return ac_ctr.blob


if __name__ == "__main__":

    print "AC test"

    sfd = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    #sfd.connect('./acd.socket')
    sfd.connect('/Users/eau/dev/go/acd.socket')

    # this is the public key generation request
    # PKGEN request
#    acpkreq = ac_pb2.acPublicKeyMessageRequest()
#    acpkreq.type = ac_pb2.acPublicKeyMessageRequest.PK_GEN
#    acpkreq.nick = "spotyooii"
    
    
    # let's build the overall message.
#    acmsg = ac_pb2.ArseneCryptoMessage()
    #acmsg.type = ac_pb2.ArseneCryptoMessage.AC_PK
    # let put and invalid message...
#    acmsg.type = ac_pb2.ArseneCryptoMessage.AC_KEX
#    acmsg.blob = acpkreq.SerializeToString()
    
#    acblob = acmsg.SerializeToString()
#    myargs = { KEY_NICK:"jambonnnn", KEY_HOST:KEY_HOST_DATA, KEY_SERVER:KEY_SERVER_DATA, KEY_BLOB:"ddskjdkdjsakjdasksa" }


#   NEW KEY PAIR
    pk_getnewpair(sfd)

#   NEW GET MY PUBLIC KEY
#    pk_getmypubkey(sfd)

#   ADD A NEW PUBKEY
#    pk_addpubkey(sfd)

#   PK_LIST
    pk_list(sfd)

#   PK_DEL
#    pk_del(sfd)

#   KX_PACK
#    DATA_BLOB = kx_sendkey(sfd)

#    print "DA BLOB:"
#    print DATA_BLOB

#   KX_UNPACK
#    kx_recvkey(sfd)


#   CT_SEAL
#    DATA_BLOB = ct_seal(sfd)

#   CT_OPEN
#    ct_open(sfd)

#    while (1):
#        pk_getnewpair(sfd)
#        print "KJDSKJDASJKDASKDASLKDJASKJDASKDLASJDASKJDLAJKSDKASJDAJKSLDJLAKSJDSALK"
#time.sleep(1)
#        pk_getmypubkey(sfd)
#        time.sleep(1)
    
#        pk_addpubkey(sfd)

#time.sleep(10)
    sfd.close()

