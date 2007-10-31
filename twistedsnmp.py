import netsnmp
from CONSTANTS import *

from twisted.internet import reactor
from twisted.internet.error import TimeoutError
from twisted.internet.interfaces import IReadDescriptor
from twisted.python import failure
from twisted.internet import defer

from sets import Set

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
    current = Set(fdMap.keys())
    need = Set(fds)
    doomed = current - need
    for d in doomed:
        reactor.removeReader(fdMap[d])
        del fdMap[d]
    if timer.callLater:
        timer.callLater.cancel()
        timer.callLater = None
    if t is not None:
        timer.callLater = reactor.callLater(t, checkTimeouts)

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
                 tries = 3,
                 cmdLineArgs = ()):
        self.ip = ip
        self.port = port
        self.community = community
        self.snmpVersion = snmpVersion
        self.timeout = timeout
        self.tries = tries
        self.cmdLineArgs = cmdLineArgs
        self.defers = {}
        self.session = None

    def callback(self, pdu):
        result = {}
        response = netsnmp.getResult(pdu)
        d = self.defers.pop(pdu.reqid)
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

    def _getCmdLineArgs(self):
        version = str(self.snmpVersion).lstrip('v')
        if version == '2':
            version += 'c'
        if self.session is not None:
            self.session.close()
            self.session = None
        cmdLineArgs = list(self.cmdLineArgs) + ['-v', str(version),
                                                '-c', self.community,
                                                '-t', str(self.timeout),
                                                '-r', str(self.tries),
                                                '%s:%d' % (self.ip, self.port)]
        return cmdLineArgs

    def open(self):
        self.session = netsnmp.Session(cmdLineArgs=self._getCmdLineArgs())
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
        try:
            self.defers[self.session.get(translateOids(oids))] = d
        except Exception, ex:
            return defer.fail(ex)
        updateReactor()
        return d

    def walk(self, oid, timeout=None, retryCount=None):
        d = defer.Deferred()
        try:
            self.defers[self.session.walk(translateOid(oid))] = d
        except Exception, ex:
            return defer.fail(ex)
        updateReactor()
        return d

    def getbulk(self, nonrepeaters, maxrepititions, oids):
        d = defer.Deferred()
        try:
            self.defers[self.session.getbulk(nonrepeaters,
                                             maxrepititions,
                                             translateOids(oids))] = d
        except Exception, ex:
            return defer.fail(ex)
        updateReactor()
        return d

    def getTable(self, oids, **kw):
        from tableretriever import TableRetriever
        try:
            t = TableRetriever(self, oids, **kw)
        except Exception, ex:
            return defer.fail(ex)
        updateReactor()
        return t()

class _FakeProtocol:
    protocol = None
    def port(self): return self
snmpprotocol = _FakeProtocol()

