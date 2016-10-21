#!/usr/bin/env python
import json
import base64

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

class AcJSCom(object):
    # depending on the type of data  we might need more space
    BUF_SMALL   = 2048
    BUF_LARGE   = 65536
    BUF_XXL     = 1048576

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
        # XXX daemon should stop properly and not with a terminate
        #self.acProc.terminate()
        # XXX TODO check return code to see if it's out.
        #self.acProc.returncode
        # XXX TODO that or terminate, let's go with terminate first..
        #acblob = self.acMsg(ACMSG_TYPE_QUIT, 0, None)
        #ac_pkr, err = self.acRequest(acblob, 0, BUF_LARGE)
        ac_quit, err = self.acRequest(self.ACMSG_TYPE_QUIT, 0, None, self.BUF_LARGE)
        if ac_quit and ac_quit.type == ac_pb2.ArseneCryptoMessage.AC_QUIT:
            print "QUIT BLOB: %s\n" % ac_quit.blob
        else:
            print "QUIT ERROR!"
        return None

class acMessage(object):
    msgtype = 0
    msgdata = ""
    acDict = {}

    # depending on the type of data  we might need more space
    BUF_SMALL   = 2048
    BUF_LARGE   = 65536
    BUF_XXL     = 1048576

    def __init__(self, msgtype):
        if msgtype in msgTypeEnum:
            self.msgtype = getattr(msgTypeEnum, msgtype)
            self.acDict['type'] = self.msgtype
            self.acDict['payload'] = ""
    def pack(self, payload):
        self.acDict['payload'] = payload
        return json.dumps(self.acDict)
    # XXX TODO: add the send()/recv() function to the socket stdin/stdout etc...
        
class kxMessage(acMessage):
    serv = ""
    chan = ""
    kxDict = {}
    def __init__(self, server, channel):
        acMessage.__init__(self, 'KXMSG')
        self.serv = server
        self.chan = channel

    def pack(self):
        # encode the payload before putting in the enveloppe
        kxDictDump = base64.b64encode(json.dumps(self.kxDict))
        # calling parent pack() to build the enveloppe
        return super(kxMessage, self).pack(kxDictDump)

    def kxpack(self, me, peernick):
        self.kxDict['type'] = getattr(msgTypeEnum, 'KXPACK')
        self.kxDict['server'] = self.serv
        self.kxDict['channel'] = self.chan
        self.kxDict['me'] = me
        self.kxDict['peer'] = peernick
        return self.pack()

    def kxunpack(self, me, peernick, blob):
        self.kxDict['type'] = getattr(msgTypeEnum, 'KXPACK')
        self.kxDict['server'] = self.serv
        self.kxDict['channel'] = self.chan
        self.kxDict['me'] = me
        self.kxDict['peer'] = peernick
        self.kxDict['blob'] = blob
        return self.pack()


class ctMessage(acMessage):
    serv = ""
    chan = ""
    ctDict = {}
    def __init__(self, server, channel):
        acMessage.__init__(self, 'CTMSG')
        self.serv = server
        self.chan = channel
        self.ctDict = {}

    def pack(self):
        # encode the payload before putting in the enveloppe
        ctDictDump = base64.b64encode(json.dumps(self.ctDict))
        # calling parent pack() to build the enveloppe
        return super(ctMessage, self).pack(ctDictDump)

    def ctseal(self, me, plain):
        self.ctDict['type'] = getattr(msgTypeEnum, 'CTSEAL')
        self.ctDict['server'] = self.serv
        self.ctDict['channel'] = self.chan
        self.ctDict['nick'] = me
        # remember when using []byte() in Go you need to base64 encode it..
        self.ctDict['blob'] = base64.b64encode(plain)
        return self.pack()

    def ctopen(self, peer, ciphertext, opt):
        self.ctDict['type'] = getattr(msgTypeEnum, 'CTOPEN')
        self.ctDict['server'] = self.serv
        self.ctDict['channel'] = self.chan
        self.ctDict['nick'] = peer
        self.ctDict['blob'] = base64.b64encode(ciphertext)
        self.ctDict['opt'] = base64.b64encode(opt)
        return self.pack()

    def ctadd(self, me, inputblob):
        self.ctDict['type'] = getattr(msgTypeEnum, 'CTADD')
        self.ctDict['server'] = self.serv
        self.ctDict['channel'] = self.chan
        self.ctDict['nick'] = me
        self.ctDict['blob'] = base64.b64encode(inputblob)
        return self.pack()


class clMessage(acMessage):
    serv = ""
    chan = ""
    clDict = {}
    def __init__(self, server, channel):
        acMessage.__init__(self, 'CLMSG')
        self.serv = server
        self.chan = channel
        self.clDict = {}

    def pack(self):
        # encode the payload before putting in the enveloppe
        clDictDump = base64.b64encode(json.dumps(self.clDict))
        # calling parent pack() to build the enveloppe
        return super(clMessage, self).pack(clDictDump)

    def clload(self, p):
        self.clDict['type'] = getattr(msgTypeEnum, 'CLLOAD')
        self.clDict['server'] = self.serv
        self.clDict['channel'] = self.chan
        self.clDict['blob'] = base64.b64encode(p)
        return self.pack()

    def clsave(self, p):
        self.clDict['type'] = getattr(msgTypeEnum, 'CLSAVE')
        self.clDict['server'] = self.serv
        self.clDict['channel'] = self.chan
        self.clDict['blob'] = base64.b64encode(p)
        return self.pack()

#    is AC?
    def cliac(self):
        self.clDict['type'] = getattr(msgTypeEnum, 'CLIAC')
        self.clDict['server'] = self.serv
        self.clDict['channel'] = self.chan
        return self.pack()


class pkMessage(acMessage):
    serv = ""
    blob = ""
    pkDict = {}
    def __init__(self, server):
        acMessage.__init__(self, 'PKMSG')
        self.serv = server

    def pack(self):
        # encode the payload before putting in the enveloppe
        pkDictDump = base64.b64encode(json.dumps(self.pkDict))
        # calling parent pack() to build the enveloppe
        return super(pkMessage, self).pack(pkDictDump)

    def pkgen(self, nick, host):
        self.pkDict['type'] = getattr(msgTypeEnum, 'PKGEN')
        self.pkDict['server'] = self.serv
        self.pkDict['nick'] = nick
        self.pkDict['host'] = host
        return self.pack()

    def pkadd(self, nick, host, blob):
        self.pkDict['type'] = getattr(msgTypeEnum, 'PKADD')
        self.pkDict['server'] = self.serv
        self.pkDict['nick'] = nick
        self.pkDict['host'] = host
        self.pkDict['blob'] = base64.b64encode(blob)
        return self.pack()

    def pklist(self, nick):
        self.pkDict['type'] = getattr(msgTypeEnum, 'PKLIST')
        self.pkDict['server'] = self.serv
        self.pkDict['nick'] = nick
        return self.pack()

    def pkdel(self, nick):
        # if nick is empty don't do anything...
        self.pkDict['type'] = getattr(msgTypeEnum, 'PKDEL')
        self.pkDict['server'] = self.serv
        self.pkDict['nick'] = nick
        return self.pack()



if __name__ == "__main__":
#    print "MAIN CODE"
    # PK MESSAGES
    print "-----"
    print "PKGEN Message (spoty):"
    pk = pkMessage("freenode").pkgen("spoty", "eau@prout.org")
    print pk
    print "PKGEN Message (bleh):"
    pk = pkMessage("freenode").pkgen("bleh", "eau@prout.org")
    print pk

    print "-----"
    print "PKADD Message:"
    pk = pkMessage("freenode").pkadd("apeer", "eau@prout.org", "DaKT5RIaLnjaut+hZfqr07VZIkd+/zeTlLMcF0R/39i9+qVav6daPfsnS0AAAAD//wZmD7M=")
    print pk

    print "-----"
    print "PKLIST Message:"
    print "spoty:"
    pk = pkMessage("freenode").pklist("spoty")
    print pk
    print "ALL:"
    pk = pkMessage("freenode").pklist("")
    print pk

    print "-----"
    print "PKDEL Message:"
    pk = pkMessage("freenode").pkdel("spoty")
    print pk

    print "-----"
    # KX MESSAGES
    print "KXPACK Message:"
    kx = kxMessage("freenode", "#ermites").kxpack("spoty", "nitro")
    print kx

    print "KXUNPACK Message:"
    ukx = kxMessage("freenode", "#ermites").kxunpack("spoty", "nitro", "blobbleh")
    print ukx

    print "-----"
    # ct MESSAGES
    print "CTSEAL Message (bleh):"
    ct = ctMessage("freenode", "#ermites").ctseal("bleh", "plaintext")
    print ct

    print "CTOPEN Message (spoty):"
    ct = ctMessage("freenode", "#ermites").ctopen("spoty", "RFFrd2pSb1FBQm9sTS9qbTRGdWttR0xSZkxLNnNDWm9ORUNLMTZ6VGowUmQyeEszanp2T244NkVKb2toV0E9PQ==", "bleh")
    print ct

    print "CTOPEN Message (bleh):"
    ct = ctMessage("freenode", "#ermites").ctopen("bleh", "DYswjzAaJUsCNDNSZxPraDcBG4x1kojTEZlvxbKyAaW4HLUb+UP7Ur6/nMU=", "")
    print ct

    print "CTADD Message:"
    ctu = ctMessage("freenode", "#ermites").ctadd("spoty", "someuuurandomkeygarbage")
    print ctu

    print "-----"
    print "CLIAC Message:"
    cl = clMessage("freenode", "#ermites").cliac()
    print cl

#    yu = json.dumps(msg.__dict__)
#    print yu
#    te = json.loads(yu)
#    print msg
#    print te
