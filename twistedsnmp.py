import netsnmp
from CONSTANTS import *

from ipaddr import IPAddress

from twisted.internet import reactor
from twisted.internet.error import TimeoutError
from twisted.internet.interfaces import IReadDescriptor
from twisted.python import failure
from twisted.internet import defer

import logging
log = logging.getLogger('zen.twistedsnmp')

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
    if log.getEffectiveLevel() < logging.DEBUG:
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

class SnmpError(Exception): pass
class SnmpNameError(Exception):
    def __init__(self, oid):
        Exception.__init__(self, 'Bad Name', oid)


def asOidStr(oid):
    """converts an oid int sequence to an oid string"""
    return '.'+'.'.join([str(x) for x in oid])


def asOid(oidStr):
    """converts an OID string into a tuple of integers"""
    return tuple([int(x) for x in oidStr.strip('.').split('.')])

def _get_agent_spec(ipobj, interface, port):
    """take a google ipaddr object and port number and produce a net-snmp
    agent specification (see the snmpcmd manpage)"""
    if ipobj.version == 4:
        agent = "udp:%s:%s" % (ipobj.compressed, port)
    elif ipobj.version == 6:
        if ipobj.is_link_local:
            if interface is None:
                raise RuntimeError("Cannot create agent specification from link local IPv6 address without an interface")
            else:
                agent = "udp6:[%s%%%s]:%s" % (ipobj.compressed, interface, port)
        else:
            agent = "udp6:[%s]:%s" % (ipobj.compressed, port)
    else:
        raise RuntimeError("Cannot create agent specification for IP address version: %s" % ipobj.version)
    return agent

class Snmpv3Error(Exception):

    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message

    def __repr__(self):
        return self.message

USM_STATS_OIDS = {

    # usmStatsWrongDigests
    ".1.3.6.1.6.3.15.1.1.5.0":
    "check zSnmpAuthType and zSnmpAuthPassword, packet did not include the expected digest value",

    # usmStatsUnknownUserNames
    ".1.3.6.1.6.3.15.1.1.3.0":
    "check zSnmpSecurityName, packet referenced an unknown user",

    # usmStatsUnsupportedSecLevels
    ".1.3.6.1.6.3.15.1.1.1.0":
    "packet requested an unknown or unavailable security level",

    # usmStatsDecryptionErrors
    ".1.3.6.1.6.3.15.1.1.6.0":
    "check zSnmpPrivType, packet could not be decrypted"

}

class AgentProxy(object):
    """The public methods on AgentProxy (get, walk, getbulk) expect input OIDs
    to be strings, and the result they produce is a dictionary.  The 
    dictionary keys are OID strings and the values are the values returned by
    the SNMP requests.
    
    The private methods (_get, _walk, _getbulk) expect input OIDs to be tuples
    of integers.  These methods generate a result that is a list of pairs, 
    each pair consisting of the OID string and the value that is returned by
    the SNMP query. The list is ordered correctly by the OID (i.e. it is not 
    ordered by the OID string)."""

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
        """netsnmp session callback"""
        result = []
        response = netsnmp.getResult(pdu)

        try:
            d = self.defers.pop(pdu.reqid)
        except KeyError:
            # We seem to end up here if we use bad credentials with authPriv.
            # The only reasonable thing to do is call all of the deferreds with
            # Snmpv3Errors.
            for usmStatsOid, count in response:
                usmStatsOidStr = asOidStr(usmStatsOid)
                
                if usmStatsOidStr == ".1.3.6.1.6.3.15.1.1.2.0":
                    # Some devices use usmStatsNotInTimeWindows as a normal part of the SNMPv3 handshake (JIRA-1565)
                    # net-snmp automatically retries the request with the previous request_id and the values for
                    # msgAuthoritativeEngineBoots and msgAuthoritativeEngineTime from this error packet
                    log.debug("Received a usmStatsNotInTimeWindows error. Some devices use usmStatsNotInTimeWindows as a normal part of the SNMPv3 handshake.")
                    return
                
                default_msg = "packet dropped (OID: {0})".format(usmStatsOidStr)
                message = USM_STATS_OIDS.get(usmStatsOidStr, default_msg)
                break
            else:
                message = "packet dropped"

            for d in (d for d in self.defers.values() if not d.called):
                reactor.callLater(0, d.errback, failure.Failure(Snmpv3Error(message)))

            return

        for oid, value in response:
            if isinstance(value, tuple):
                value = asOidStr(value)
            result.append((oid, value))
        if pdu.errstat != netsnmp.SNMP_ERR_NOERROR:
            # fixme: we can do better: use errback
            m = PDU_ERRORS.get(pdu.errstat, 'Unknown error (%d)' % pdu.errstat)
            # log.warning("Packet for %s has error: %s", self.ip, m)
            result = []
        reactor.callLater(0, d.callback, result)

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

        if '%' in self.ip:
            address, interface = self.ip.split('%')
        else:
            address = self.ip
            interface = None

        log.debug("AgentProxy._getCmdLineArgs: using google ipaddr on %s" % address)
        ipobj = IPAddress(address)
        agent = _get_agent_spec(ipobj, interface, self.port)

        cmdLineArgs = list(self.cmdLineArgs) + ['-v', str(version),
                                                '-c', self.community,
                                                '-t', str(self.timeout),
                                                '-r', str(self.tries),
                                                agent,
                                               ]
        return cmdLineArgs

    def open(self):
        self.session = netsnmp.Session(cmdLineArgs=self._getCmdLineArgs())
        self.session.callback = self.callback
        self.session.timeout = self.timeout_
        self.session.open()
        updateReactor()

    def close(self):
        # Changing this to something sane causes zenperfsnmp to blow up
        # Trac http://dev.zenoss.org/trac/ticket/6354
        assert self.session

        self.session.close()
        self.session = None
        updateReactor()

    def _get(self, oids, timeout=None, retryCount=None):
        d = defer.Deferred()
        try:
            self.defers[self.session.get(oids)] = d
        except Exception, ex:
            return defer.fail(ex)
        updateReactor()
        return d

    def _walk(self, oid, timeout=None, retryCount=None):
        d = defer.Deferred()
        try:
            self.defers[self.session.walk(oid)] = d
        except netsnmp.SnmpTimeoutError:
            return defer.fail(TimeoutError())
        except Exception, ex:
            return defer.fail(ex)
        updateReactor()
        return d

    def _getbulk(self, nonrepeaters, maxrepititions, oids):
        d = defer.Deferred()
        try:
            self.defers[self.session.getbulk(nonrepeaters,
                                             maxrepititions,
                                             oids)] = d
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
        
    def get(self, oidStrs, timeout=None, retryCount=None):
        oids = [asOid(oidStr) for oidStr in oidStrs]
        deferred = self._get(oids, timeout, retryCount)
        deferred.addCallback(self._convertToDict)
        return deferred

    def walk(self, oidStr, timeout=None, retryCount=None):
        deferred = self._walk(asOid(oidStr), timeout, retryCount)
        deferred.addCallback(self._convertToDict)
        return deferred

    def getbulk(self, nonrepeaters, maxrepititions, oidStrs):
        oids = [asOid(oidStr) for oidStr in oidStrs]
        deferred = self._getbulk(nonrepeaters, maxrepititions, oids)
        deferred.addCallback(self._convertToDict)
        return deferred

    def _convertToDict(self, result):
        def strKey(item):
            return asOidStr(item[0]), item[1]

        if isinstance(result, list):
            return dict(map(strKey, result))
        return result


class _FakeProtocol:
    protocol = None
    def port(self): return self
snmpprotocol = _FakeProtocol()

