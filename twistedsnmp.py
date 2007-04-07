import netsnmp
from CONSTANTS import *

from twisted.internet import reactor
from twisted.internet.error import TimeoutError
from twisted.internet.interfaces import IReadDescriptor
from twisted.python import failure
from twisted.internet import defer

import logging
log = logging.getLogger('twistedsnmp')

class Timer(object):
    callLater = None
timer = Timer()
fdMap = {}

PDU_ERRORS = {
    SNMP_ERR_NOERROR: "We have no problems here",
    SNMP_ERR_TOOBIG: "Packet too big",
    SNMP_ERR_NOSUCHNAME: "Unknown oid",
    SNMP_ERR_BADVALUE: "Bad value",
    SNMP_ERR_READONLY: "Oid is read-only",
    SNMP_ERR_GENERR: "General error",
    SNMP_ERR_NOACCESS: "Permission denied",
    SNMP_ERR_WRONGTYPE: "Wrong type",
    SNMP_ERR_WRONGLENGTH: "Bad length",
    SNMP_ERR_WRONGENCODING: "Bad encoding",
    SNMP_ERR_WRONGVALUE: "Bad value",
    SNMP_ERR_NOCREATION: "No creation",
    SNMP_ERR_INCONSISTENTVALUE: "Inconsistent value",
    SNMP_ERR_RESOURCEUNAVAILABLE:  "Resource unavailable",
    SNMP_ERR_COMMITFAILED: "Commit failed",
    SNMP_ERR_UNDOFAILED: "Undo failed",
    SNMP_ERR_AUTHORIZATIONERROR: "Authorization error",
    SNMP_ERR_NOTWRITABLE: "Not writable",
    SNMP_ERR_INCONSISTENTNAME: "Inconsistent name",
    }

def checkTimeouts():
    "Handle timeouts for Net-SNMP"
    timer.callLater = None
    netsnmp.lib.snmp_timeout()
    updateReactor()


class SnmpReader: #(IReadDescriptor):
    "Respond to input events"

    def logPrefix(self):
        return 'SnmpReader'

    def __init__(self, fd):
        self.fd = fd

    def doRead(self):
        netsnmp.snmp_read(self.fd)
        # updateReactor()

    def fileno(self):
        return self.fd

    def connectionLost(self, why):
        del fdMap[self.fd]

def updateReactor():
    "Add/remove event handlers for SNMP file descriptors and timers"

    fds, t = netsnmp.snmp_select_info()
    log.debug('reactor settings: %r, %r', fds, t)
    for fd in fds:
        if fd not in fdMap:
            reader = SnmpReader(fd)
            fdMap[fd] = reader
            reactor.addReader(reader)
    current = set(fdMap.keys())
    need = set(fds)
    doomed = current - need
    for d in doomed:
        reactor.removeReader(fdMap[d])
        del fdMap[d]
    if timer.callLater:
        timer.callLater.cancel()
        timer.callLater = None
    if t is not None:
        timer.callLater = reactor.callLater(t, checkTimeouts)

VERSION_MAP = {
    'v1': netsnmp.SNMP_VERSION_1,
    '1': netsnmp.SNMP_VERSION_1,
    'v2': netsnmp.SNMP_VERSION_2c,
    'v2c': netsnmp.SNMP_VERSION_2c,
    '2': netsnmp.SNMP_VERSION_2c,
    '2c': netsnmp.SNMP_VERSION_2c,
    'v3': netsnmp.SNMP_VERSION_3,
    '3': netsnmp.SNMP_VERSION_3,
    }

class SnmpError(Exception): pass
class SnmpNameError(Exception):
    def __init__(self, oid):
        Exception.__init__(self, 'Bad Name', oid)

def translateOid(oid):
    return tuple(map(int, oid.strip('.').split('.')))

def translateOids(oids):
    return [translateOid(oid) for oid in oids]    

class AgentProxy:

    def __init__(self,
                 ip,
                 port=161, 
                 community='public',
                 snmpVersion = '1', 
                 protocol=None,
                 allowCache = False,
                 timeout = 1.5,
                 tries = 3):
        self.ip = ip
        self.port = port
        self.community = community
        self.snmpVersion = snmpVersion
        self.timeout = timeout
        self.tries = tries
        self.defers = {}
        self.session = None

    def callback(self, pdu):
        result = {}
        d = self.defers.pop(pdu.reqid)
        response = netsnmp.getResult(pdu)
        for oid, value in response:
            oid = '.' + '.'.join(map(str, oid))
            if isinstance(value, tuple):
                value = '.' + '.'.join(map(str, value))
            result[oid] = value
        if pdu.errstat != netsnmp.SNMP_ERR_NOERROR:
            # fixme: we can do better: use errback
            m = PDU_ERRORS.get(pdu.errstat, 'Unknown error (%d)' % pdu.errstat)
            # log.warning("Packet for %s has error: %s", self.ip, m)
            result = {}
        reactor.callLater(0, d.callback, result )
            
    def timeout_(self, reqid):
        d = self.defers.pop(reqid)
        reactor.callLater(0, d.errback, failure.Failure(TimeoutError()))

    def open(self):
        version = VERSION_MAP.get(self.snmpVersion)
        self.ip, version
        assert self.session is None
        self.session = netsnmp.Session(peername=self.ip,
                                       community=self.community,
                                       community_len=len(self.community),
                                       version=version,
                                       timeout=int(self.timeout*1e6),
                                       retries=self.tries)
        self.session.callback = self.callback
        self.session.timeout = self.timeout_
        self.session.open()
        updateReactor()

    def close(self):
        assert self.session
        self.session.close()
        self.session = None
        updateReactor()

    def get(self, oids, timeout=None, retryCount=None):
        d = defer.Deferred()
        self.defers[self.session.get(translateOids(oids))] = d
        return d

    def walk(self, oid, timeout=None, retryCount=None):
        d = defer.Deferred()
        self.defers[self.session.walk(translateOid(oid))] = d
        return d

    def getbulk(self, nonrepeaters, maxrepititions, oids):
        d = defer.Deferred()
        self.defers[self.session.getbulk(nonrepeaters,
                                         maxrepititions,
                                         translateOids(oids))] = d
        return d

    def getTable(self, oids, timeout, retryCount, maxRepetitions):
        from tableretriever import TableRetriever
        t = TableRetriever(self, oids, timeout, retryCount, maxRepetitions)
        return t()

class _FakeProtocol:
    protocol = None
    def port(self): return self
snmpprotocol = _FakeProtocol()

