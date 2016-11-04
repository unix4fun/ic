#!/usr/bin/env python
import json
import base64
import subprocess
import fcntl
#import sys
import os
import binascii
#import string
#import ast
import datetime
import select
#import socket
#import re
import base64
#import cgi
#import time
#import random

class Enum(tuple): 
    __getattr__ = tuple.index

#    NOMSG = 0
#    PKMSG = 1
#    KXMSG = 2
#    CTMSG = 3
#    CLMSG = 4
#    QTMSG = 5
#    ERMSG = 6


msgTypeEnum = Enum(['none', \
        'PKMSG', 'KXMSG', 'CTMSG', 'CLMSG', 'QTMSG', 'ERMSG', \
        'PKGEN', 'PKADD', 'PKLIST', 'PKDEL', \
        'R_PKGEN', 'R_PKADD', 'R_PKLIST', 'R_PKDEL', 'R_PKERR', \
        'KXPACK', 'R_KXPACK', 'KXUNPACK', 'R_KXUNPACK', 'R_KXERR', \
        'CTSEAL', 'R_CTSEAL', 'CTOPEN', 'R_CTOPEN', 'CTADD', 'R_CTADD', 'R_CTERR', \
        'CLLOAD', 'R_CLLOAD', 'CLSAVE', 'R_CLSAVE', 'CLIAC', 'R_CLIAC', 'R_CLERR' \
        ])

class acJSCom(object):
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
        if self.acDebugFile is None:
            self.acDebugFile = acDbg
            self.acDebugFd = open(acDbg, 'w')
#        try:
#            self.acDebugFd = open(acDbg, 'w')
#        except Exception as e:
#            print "cannot init IAC communication: %s." % str(e)
#
    def acStartDaemon(self):
        # XXX TODO: handle the debugging channel correctly, handle exceptions!
        if self.acProc is None:
            self.acProc = subprocess.Popen(self.acBinary, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.acDebugFd)
            flags = fcntl.fcntl(self.acProc.stdout, fcntl.F_GETFL) # get current p.stdout flags
            fcntl.fcntl(self.acProc.stdout, fcntl.F_SETFL, flags | os.O_NONBLOCK) # add non blocking
        return None

    def acStopDaemon(self):
        # XXX daemon should stop properly and not with a terminate
        #self.acProc.terminate()
        # XXX TODO check return code to see if it's out.
        #self.acProc.returncode
        # XXX TODO that or terminate, let's go with terminate first..
        #acblob = self.acMsg(ACMSG_TYPE_QUIT, 0, None)
        ac_quit, err = self.acRequest(self.ACMSG_TYPE_QUIT, 0, None, self.BUF_LARGE)
        if ac_quit and ac_quit.type == ac_pb2.ArseneCryptoMessage.AC_QUIT:
            print "QUIT BLOB: %s\n" % ac_quit.blob
        else:
            print "QUIT ERROR!"
        return None

    # return [ Blob|None, Error|None ]
    def acRequest(self, reqblob, bufsize):
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
        return [ rcvBlob, None ]


class acMessage(object):
    msgtype = 0
    msgdata = ""
    acDict = {}
    replyDict = {}

    # depending on the type of data  we might need more space
    BUF_SMALL   = 2048
    BUF_LARGE   = 65536
    BUF_XXL     = 1048576

    def __init__(self, msgtype):
        self.acDict = {}
        self.replyDict = {}
        if msgtype in msgTypeEnum:
            self.msgtype = getattr(msgTypeEnum, msgtype)
            self.acDict['type'] = self.msgtype
            self.acDict['payload'] = ""

    def pack(self, payload):
        self.acDict['payload'] = payload
        return json.dumps(self.acDict)
    # XXX TODO: add the send()/recv() function to the socket stdin/stdout etc...

    def unpack(self, blob):
        self.replyDict = json.loads(blob)
        if self.replyDict["type"] == self.msgtype or self.replyDict["type"] == getattr(msgTypeEnum, 'ERMSG'):
#            print "REPLY REPLY #0 (no base64):"
#            print self.replyDict["payload"]
            return self.replyDict["payload"]
#            print "REPLY REPLY #1 (no base64):"
#            return base64.b64decode(replyDict["payload"])
        return ""


class pkMessage(acMessage):
    com = None
    serv = ""
    blob = ""
    pkDict = {}
    def __init__(self, com, server):
        acMessage.__init__(self, 'PKMSG')
        self.serv = server
        self.pkDict = {}
        self.com = com

    def pack(self):
        # encode the payload before putting in the enveloppe
        pkDictDump = base64.b64encode(json.dumps(self.pkDict))
        # calling parent pack() to build the enveloppe
        return super(pkMessage, self).pack(pkDictDump)

    def unpack(self, blob):
        # decode the enveloppe first
        payload = super(pkMessage, self).unpack(blob)
        pkReplyDict = base64.b64decode(payload)
        return json.loads(pkReplyDict)

    def pkgen(self, nick, host):
        self.pkDict['type'] = getattr(msgTypeEnum, 'PKGEN')
        self.pkDict['server'] = self.serv
        self.pkDict['nick'] = nick
        self.pkDict['host'] = host
        packed = self.pack()
        envp = self.com.acRequest(packed, self.com.BUF_LARGE)
        # XXX test ERROR first!!
        return self.unpack(envp[0])

    def pkadd(self, nick, host, blob):
        self.pkDict['type'] = getattr(msgTypeEnum, 'PKADD')
        self.pkDict['server'] = self.serv
        self.pkDict['nick'] = nick
        self.pkDict['host'] = host
#        self.pkDict['blob'] = base64.b64encode(blob)
        self.pkDict['blob'] = blob
        packed = self.pack()
        envp = self.com.acRequest(packed, self.com.BUF_LARGE)
        # XXX test ERROR first!!
        return self.unpack(envp[0])

    def pklist(self, nick):
        self.pkDict['type'] = getattr(msgTypeEnum, 'PKLIST')
        self.pkDict['server'] = self.serv
        self.pkDict['nick'] = nick
        packed = self.pack()
        envp = self.com.acRequest(packed, self.com.BUF_LARGE)
        # XXX test ERROR first!!
        rep =  self.unpack(envp[0])
        #rep['blob'] = base64.b64decode(rep['blob'])
        rep['blob'] = json.loads(rep['blob'])
        return rep

    def pkdel(self, nick):
        # if nick is empty don't do anything...
        self.pkDict['type'] = getattr(msgTypeEnum, 'PKDEL')
        self.pkDict['server'] = self.serv
        self.pkDict['nick'] = nick
        packed = self.pack()
        envp = self.com.acRequest(packed, self.com.BUF_LARGE)
        # XXX test ERROR first!!
        return self.unpack(envp[0])


class kxMessage(acMessage):
    com = None
    serv = ""
    chan = ""
    kxDict = {}
    def __init__(self, com, server, channel):
        acMessage.__init__(self, 'KXMSG')
        self.serv = server
        self.chan = channel
        self.kxDict = {}
        self.com = com

    def pack(self):
        # encode the payload before putting in the enveloppe
        kxDictDump = base64.b64encode(json.dumps(self.kxDict))
        # calling parent pack() to build the enveloppe
        return super(kxMessage, self).pack(kxDictDump)

    def unpack(self, blob):
        # decode the enveloppe first
        payload = super(kxMessage, self).unpack(blob)
        kxReplyDict = base64.b64decode(payload)
        return json.loads(kxReplyDict)

    def kxpack(self, me, peernick):
        self.kxDict['type'] = getattr(msgTypeEnum, 'KXPACK')
        self.kxDict['server'] = self.serv
        self.kxDict['channel'] = self.chan
        self.kxDict['me'] = me
        self.kxDict['peer'] = peernick
        packed = self.pack()
        envp = self.com.acRequest(packed, self.com.BUF_LARGE)
        # XXX test ERROR first!!
        return self.unpack(envp[0])

    def kxunpack(self, me, peernick, blob):
        self.kxDict['type'] = getattr(msgTypeEnum, 'KXUNPACK')
        self.kxDict['server'] = self.serv
        self.kxDict['channel'] = self.chan
        self.kxDict['me'] = me
        self.kxDict['peer'] = peernick
        self.kxDict['blob'] = blob
        packed = self.pack()
        envp = self.com.acRequest(packed, self.com.BUF_LARGE)
        # XXX test ERROR first!!
        return self.unpack(envp[0])

class ctMessage(acMessage):
    com = None
    serv = ""
    chan = ""
    ctDict = {}
    def __init__(self, com, server, channel):
        acMessage.__init__(self, 'CTMSG')
        self.serv = server
        self.chan = channel
        self.ctDict = {}
        self.com = com

    def pack(self):
        # encode the payload before putting in the enveloppe
        ctDictDump = base64.b64encode(json.dumps(self.ctDict))
        # calling parent pack() to build the enveloppe
        return super(ctMessage, self).pack(ctDictDump)

    def unpack(self, blob):
        # decode the enveloppe first
        payload = super(ctMessage, self).unpack(blob)
        ctReplyDict = base64.b64decode(payload)
        return json.loads(ctReplyDict)

    def ctseal(self, me, plain):
        self.ctDict['type'] = getattr(msgTypeEnum, 'CTSEAL')
        self.ctDict['server'] = self.serv
        self.ctDict['channel'] = self.chan
        self.ctDict['nick'] = me
        # remember when using []byte() in Go you need to base64 encode it..
        #self.ctDict['blob'] = base64.b64encode(plain)
        self.ctDict['blob'] = plain
#        return self.pack()
        packed = self.pack()
        envp = self.com.acRequest(packed, self.com.BUF_LARGE)
        # XXX test ERROR first!!
        return self.unpack(envp[0])

    def ctopen(self, peer, ciphertext, opt):
        self.ctDict['type'] = getattr(msgTypeEnum, 'CTOPEN')
        self.ctDict['server'] = self.serv
        self.ctDict['channel'] = self.chan
        self.ctDict['nick'] = peer
        #self.ctDict['blob'] = base64.b64encode(ciphertext)
        self.ctDict['blob'] = ciphertext
        self.ctDict['opt'] = opt
#        return self.pack()
        packed = self.pack()
        envp = self.com.acRequest(packed, self.com.BUF_LARGE)
        # XXX test ERROR first!!
        return self.unpack(envp[0])

    def ctadd(self, me, inputblob):
        self.ctDict['type'] = getattr(msgTypeEnum, 'CTADD')
        self.ctDict['server'] = self.serv
        self.ctDict['channel'] = self.chan
        self.ctDict['nick'] = me
        #self.ctDict['blob'] = base64.b64encode(inputblob)
        self.ctDict['blob'] = inputblob
#        return self.pack()
        packed = self.pack()
        envp = self.com.acRequest(packed, self.com.BUF_LARGE)
        # XXX test ERROR first!!
        return self.unpack(envp[0])


class clMessage(acMessage):
    com = None
    serv = ""
    chan = ""
    clDict = {}
    def __init__(self, com):
        acMessage.__init__(self, 'CLMSG')
#        self.serv = server
#        self.chan = channel
        self.clDict = {}
        self.com = com

    def pack(self):
        # encode the payload before putting in the enveloppe
        clDictDump = base64.b64encode(json.dumps(self.clDict))
        # calling parent pack() to build the enveloppe
        return super(clMessage, self).pack(clDictDump)

    def unpack(self, blob):
        # decode the enveloppe first
        payload = super(clMessage, self).unpack(blob)
        clReplyDict = base64.b64decode(payload)
        return clReplyDict

    def clload(self, p):
        self.clDict['type'] = getattr(msgTypeEnum, 'CLLOAD')
        self.clDict['server'] = self.serv
        self.clDict['channel'] = self.chan
        self.clDict['blob'] = base64.b64encode(p)
        packed = self.pack()
        envp = self.com.acRequest(packed, self.com.BUF_LARGE)
        # XXX test ERROR first!!
        return self.unpack(envp[0])

    def clsave(self, p):
        self.clDict['type'] = getattr(msgTypeEnum, 'CLSAVE')
        self.clDict['server'] = self.serv
        self.clDict['channel'] = self.chan
        self.clDict['blob'] = base64.b64encode(p)
        packed = self.pack()
        envp = self.com.acRequest(packed, self.com.BUF_LARGE)
        # XXX test ERROR first!!
        return self.unpack(envp[0])

    #    is AC?
    def cliac(self, server, channel):
        self.clDict['type'] = getattr(msgTypeEnum, 'CLIAC')
        self.clDict['server'] = server
        self.clDict['channel'] = channel
        packed = self.pack()
        envp = self.com.acRequest(packed, self.com.BUF_LARGE)
        # XXX test ERROR first!!
        return self.unpack(envp[0])



class qtMessage(acMessage):
    com = None
    serv = ""
    chan = ""
    qtDict = {}
    def __init__(self, com):
        acMessage.__init__(self, 'QTMSG')
        self.qtDict = {}
        self.com = com

    def pack(self):
        # encode the payload before putting in the enveloppe
        qtDictDump = base64.b64encode(json.dumps(self.qtDict))
        # calling parent pack() to build the enveloppe
        return super(qtMessage, self).pack(qtDictDump)

    def unpack(self, blob):
        # decode the enveloppe first
        payload = super(qtMessage, self).unpack(blob)
        if payload is None:
            qtReplyDict = {}
        else:
            qtReplyDict = base64.b64decode(payload)
        return qtReplyDict

    def quit(self):
#        return self.pack()
        packed = self.pack()
        envp = self.com.acRequest(packed, self.com.BUF_LARGE)
        # XXX test ERROR first!!
        return self.unpack(envp[0])



if __name__ == "__main__":
#    print "MAIN CODE"
    print "----- JSON Communication layer -----"
    jsCom = acJSCom("/Users/eau/dev/go/src/github.com/unix4fun/ic/ic", "./debuglocal")
    jsCom.acStartDaemon()


    # PK MESSAGES
    print "-----"
    print "PKGEN Message (spoty):"
    pk = pkMessage(jsCom, "freenode").pkgen("spoty", "eau@prout.org")
    print "TYPE: "
    print type(pk)
    print pk["bada"]
    print pk

    print "PKGEN Message (bleh):"
    pk = pkMessage(jsCom, "freenode").pkgen("bleh", "eau@prout.org")
    print pk

    print "-----"
    print "PKADD Message:"
    pk = pkMessage(jsCom, "freenode").pkadd("apeer", "eau@prout.org", "DaKT5RIaLnjaut+hZfqr07VZIkd+/zeTlLMcF0R/39i9+qVav6daPfsnS0AAAAD//wZmD7M=")
    print pk

    print "-----"
    print "PKLIST Message:"
    print "spoty:"
    pk = pkMessage(jsCom, "freenode").pklist("spoty")
    print pk
    print "ALL:"
    pk = pkMessage(jsCom, "freenode").pklist("")
    print pk
    print len(pk['blob'])
    for i in pk['blob']:
        print "bleh:"+i
        print pk['blob'][i]
        print pk['blob'][i]['PubFP']
        pk['blob'][i]['PubFP'] = ''.join([chr(item) for item in pk['blob'][i]['PubFP']])
        print binascii.hexlify(pk['blob'][i]['PubFP'])
        print str(datetime.datetime.fromtimestamp(pk['blob'][i]['Timestamp']))
        print type(pk['blob'][i]['PubFP'])

    print "-----"
    print "PKDEL Message:"
    pk = pkMessage(jsCom, "freenode").pkdel("spoty")
    print pk

    print "-----"
    # KX MESSAGES
    print "KXPACK Message:"
    kx = kxMessage(jsCom, "freenode", "#ermites").kxpack("spoty", "nitro")
    print kx

    print "KXUNPACK Message:"
    ukx = kxMessage(jsCom, "freenode", "#ermites").kxunpack("spoty", "nitro", "blobbleh")
    print ukx

    print "-----"

    print "CTADD Message:"
    ctu = ctMessage(jsCom, "freenode", "#ermites").ctadd("spoty", "someuuurandomkeygarbage")
    print ctu

    # ct MESSAGES
#    print "CTSEAL Message (bleh):"
#    ct = ctMessage(jsCom, "freenode", "#ermites").ctseal("bleh", "pkdsjkadjldakjdlakjdlakjdlaksjdlkasdlkasjldkajlkdajslkdjalskdakjsdlkasjdlkasjdlkajdlkajdklajdlkasjlkdasjlkdjaslkdjaslkdjaskljdaslkjdalksjdlaksjdlkasjdlkasjdlkajsdlkajdlkajslkdajslkdjaslkdjaslkdjaslkdjaslkjdalksjdalksjdlkasjdlkajsdlkasjdlkasjdlkajdlkasjdlkasjdklasjdlkasjdlkasjdlkasjdlkasjdlkasjdlkasjdlkasjdlkasjldkjaslkdjaslkdjaslkdjaslkdjaslkdjaslkadjldksajdlkasjdlkasjdalkdjakjdaskjdlksajldkjlkjdlakjlakdjlkdjlkajsdlkajlkdjakljdalkjdlkajkldjalkdjalkjakljdklajdklajdlkajlkdjalkjdakljsdlkajlkajslkdjdalkjdlkajdklajdklajdkljalkjdalkjdlkdjsalkjsdlkjdskldjlkdsjlkdajlkdsjldkasjadlskjdslkjdkladjdlkajdalkjdalksdlkaskjlaintextdkadlkdjlakjdalsjdlkasjdlkajslkdjaskjdsalkjdsalkjdajdlkajdklajkljdalkjdlkasjdlkasjdlkasjlkasjlksjdklajdlkajlkasjldkajslkdjaslkdjaslkdjaslkjdaklsjdaklsjdlkasjdlkajskldajskldjaslkdjaskldjsakljdaslkjdslakjdklsajdlkasjdlkajdlkasjlkasjlkdajlkdjaslkjslkajdlksajdlsakjdalskjdaslkj")
#    print ct
#    print type(ct['blobarray'])
#    ciphertext2 = base64.b64decode(ct['blobarray'][0])

    # ct MESSAGES
    print "CTSEAL Message (bleh):"
    ct = ctMessage(jsCom, "freenode", "#ermites").ctseal("bleh", "proutprout")
    print ct
    ciphertext = ct['blobarray'][0]
#    print "CTOPEN Message (spoty):"
#    ct = ctMessage(jsCom, "freenode", "#ermites").ctopen("spoty", "RFFrd2pSb1FBQm9sTS9qbTRGdWttR0xSZkxLNnNDWm9ORUNLMTZ6VGowUmQyeEszanp2T244NkVKb2toV0E9PQ==", "bleh")
#    print ct

    print "CTOPEN Message (bleh):"
#    ct = ctMessage(jsCom, "freenode", "#ermites").ctopen("bleh", "DYswjzAaJUsCNDNSZxPraDcBG4x1kojTEZlvxbKyAaW4HLUb+UP7Ur6/nMU=", "")
    ct = ctMessage(jsCom, "freenode", "#ermites").ctopen("bleh", ciphertext, "spoty")
    print ct


    #print "-----"
    #print "QTMSG Message:"
    #qt = qtMessage().quit()
    #print qt
#    print "-----"
#    print "CLIAC Message:"
#    cl = clMessage("freenode", "#ermites").cliac()
#    print cl


#
    print "CLIAC Message:"
    cl = clMessage(jsCom).cliac("freenode", "#ermites")
    print cl

    print "QUIT Message:"
    qt = qtMessage(jsCom).quit()
    print qt


#    yu = json.dumps(msg.__dict__)
#    print yu
#    te = json.loads(yu)
#    print msg
#    print te
