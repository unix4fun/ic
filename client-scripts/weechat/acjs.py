#!/usr/local/bin/python
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
        'CTSEAL', 'R_CTSEAL', 'CTOPEN', 'R_CTOPEN', 'CTADD', 'R_CTADD', 'R_CTERR' \
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
#    blob = ""
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
        self.ctDict['blob'] = plain
        return self.pack()

    def ctopen(self, peer, ciphertext, opt):
        self.ctDict['type'] = getattr(msgTypeEnum, 'CTOPEN')
        self.ctDict['server'] = self.serv
        self.ctDict['channel'] = self.chan
        self.ctDict['nick'] = peer
        self.ctDict['blob'] = ciphertext
        self.ctDict['opt'] = opt
        return self.pack()

    def ctadd(self, me, inputblob):
        self.ctDict['type'] = getattr(msgTypeEnum, 'CTADD')
        self.ctDict['server'] = self.serv
        self.ctDict['channel'] = self.chan
        self.ctDict['nick'] = me
        self.ctDict['blob'] = inputblob
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
        self.pkDict['blob'] = blob
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
    pk = pkMessage("freenode").pkgen("spoty", "eau@prout.org")
    print pk
    pk = pkMessage("freenode").pkadd("spoty", "eau@prout.org", "BLOBBLOBLOBLOB")
    print pk
    pk = pkMessage("freenode").pklist("spoty")
    print pk
    pk = pkMessage("freenode").pkdel("spoty")
    print pk

    # KX MESSAGES
    kx = kxMessage("freenode", "#ermites").kxpack("spoty", "nitro")
    print kx
    ukx = kxMessage("freenode", "#ermites").kxunpack("spoty", "nitro", "blobbleh")
    print ukx

    # ct MESSAGES

#    yu = json.dumps(msg.__dict__)
#    print yu
#    te = json.loads(yu)
#    print msg
#    print te
