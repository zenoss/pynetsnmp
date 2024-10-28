from __future__ import absolute_import

import logging
import struct

from twisted.internet import defer, reactor
from twisted.internet.selectreactor import SelectReactor
from twisted.internet.error import TimeoutError
from twisted.python import failure

from . import netsnmp
from .CONSTANTS import (
    SNMP_ERR_AUTHORIZATIONERROR,
    SNMP_ERR_BADVALUE,
    SNMP_ERR_COMMITFAILED,
    SNMP_ERR_GENERR,
    SNMP_ERR_INCONSISTENTNAME,
    SNMP_ERR_INCONSISTENTVALUE,
    SNMP_ERR_NOACCESS,
    SNMP_ERR_NOCREATION,
    SNMP_ERR_NOERROR,
    SNMP_ERR_NOSUCHNAME,
    SNMP_ERR_NOTWRITABLE,
    SNMP_ERR_READONLY,
    SNMP_ERR_RESOURCEUNAVAILABLE,
    SNMP_ERR_TOOBIG,
    SNMP_ERR_UNDOFAILED,
    SNMP_ERR_WRONGENCODING,
    SNMP_ERR_WRONGLENGTH,
    SNMP_ERR_WRONGTYPE,
    SNMP_ERR_WRONGVALUE,
)
from .conversions import asAgent, asOidStr, asOid
from .tableretriever import TableRetriever


class Timer(object):
    callLater = None


DEFAULT_PORT = 161
DEFAULT_TIMEOUT = 2
DEFAULT_RETRIES = 6

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
    SNMP_ERR_RESOURCEUNAVAILABLE: "Resource unavailable",
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


class SnmpReader:  # (IReadDescriptor):
    "Respond to input events"

    def logPrefix(self):
        return "SnmpReader"

    def __init__(self, fd):
        self.fd = fd

    def doRead(self):
        netsnmp.snmp_read2(self.fd)
        # updateReactor()

    def fileno(self):
        return self.fd

    def connectionLost(self, why):
        del fdMap[self.fd]


def updateReactor():
    "Add/remove event handlers for SNMP file descriptors and timers"

    isSelect = isinstance(reactor, SelectReactor)
    fds, t = netsnmp.snmp_select_info2()

    log = netsnmp._getLogger("updateReactor")
    if log.getEffectiveLevel() < logging.DEBUG:
        log.debug("reactor settings: %r, %r", fds, t)
    for fd in fds:
        if isSelect and fd > netsnmp.MAXFD:
            log.error(
                "fd > %d detected!!  "
                "This will not work properly with the SelectReactor and "
                "is being ignored.  Timeouts will occur unless you switch "
                "to EPollReactor instead!"
            )
            continue

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


class SnmpNameError(Exception):
    def __init__(self, oid):
        Exception.__init__(self, "Bad Name", oid)


class SnmpError(Exception):
    def __init__(self, message, *args, **kwargs):
        self.message = message

    def __str__(self):
        return self.message

    def __repr__(self):
        return self.message


class Snmpv3Error(SnmpError):
    pass


USM_STATS_OIDS = {
    # usmStatsWrongDigests
    ".1.3.6.1.6.3.15.1.1.5.0": (
        "check zSnmpAuthType and zSnmpAuthPassword, "
        "packet did not include the expected digest value"
    ),
    # usmStatsUnknownUserNames
    ".1.3.6.1.6.3.15.1.1.3.0": (
        "check zSnmpSecurityName, packet referenced an unknown user"
    ),
    # usmStatsUnsupportedSecLevels
    ".1.3.6.1.6.3.15.1.1.1.0": (
        "packet requested an unknown or unavailable security level"
    ),
    # usmStatsDecryptionErrors
    ".1.3.6.1.6.3.15.1.1.6.0": (
        "check zSnmpPrivType, packet could not be decrypted"
    ),
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

    @classmethod
    def create(
        cls,
        address,
        security=None,
        timeout=DEFAULT_TIMEOUT,
        retries=DEFAULT_RETRIES,
    ):
        try:
            ip, port = address
        except ValueError:
            port = DEFAULT_PORT
            try:
                ip = address.pop(0)
            except AttributeError:
                ip = address
        return cls(
            ip,
            port=port,
            security=security,
            timeout=timeout,
            tries=retries,
        )

    def __init__(
        self,
        ip,
        port=161,
        community="public",
        snmpVersion="1",
        protocol=None,
        allowCache=False,  # no longer used
        timeout=1.5,
        tries=3,
        cmdLineArgs=(),
        security=None,
    ):
        if security is not None:
            self._security = security
            self.snmpVersion = security.version
        else:
            self._security = None
            self.snmpVersion = snmpVersion
        self.ip = ip
        self.port = port
        self.community = community
        self.timeout = timeout
        self.tries = tries
        self.cmdLineArgs = cmdLineArgs
        self.defers = {}
        self.session = None
        self._log = netsnmp._getLogger("agentproxy")

    def _signSafePop(self, d, intkey):
        """
        Attempt to pop the item at intkey from dictionary d.
        Upon failure, try to convert intkey from a signed to an unsigned
        integer and try to pop again.

        This addresses potential integer rollover issues caused by the fact
        that netsnmp_pdu.reqid is a c_long and the netsnmp_callback function
        pointer definition specifies it as a c_int.  See ZEN-4481.
        """
        try:
            return d.pop(intkey)
        except KeyError as ex:
            if intkey < 0:
                self._log.debug("Negative ID for _signSafePop: %s", intkey)
                # convert to unsigned, try that key
                uintkey = struct.unpack("I", struct.pack("i", intkey))[0]
                try:
                    return d.pop(uintkey)
                except KeyError:
                    # Nothing by the unsigned key either,
                    # throw the original KeyError for consistency
                    raise ex
            raise

    def callback(self, pdu):
        """netsnmp session callback"""
        response = netsnmp.getResult(pdu, self._log)

        try:
            d, oids_requested = self._pop_requested_oids(pdu, response)
        except RuntimeError:
            return

        result = tuple(
            (oid, asOidStr(value) if isinstance(value, tuple) else value)
            for oid, value in response
        )

        if len(result) == 1 and result[0][0] not in oids_requested:
            usmStatsOidStr = asOidStr(result[0][0])
            if usmStatsOidStr in USM_STATS_OIDS:
                msg = USM_STATS_OIDS.get(usmStatsOidStr)
                reactor.callLater(
                    0, d.errback, failure.Failure(Snmpv3Error(msg))
                )
                return
            elif usmStatsOidStr == ".1.3.6.1.6.3.15.1.1.2.0":
                # we may get a subsequent snmp result with the correct value
                # if not the timeout will be called at some point
                self.defers[pdu.reqid] = (d, oids_requested)
                return
        if pdu.errstat != SNMP_ERR_NOERROR:
            pduError = PDU_ERRORS.get(
                pdu.errstat, "Unknown error (%d)" % pdu.errstat
            )
            message = "Packet for %s has error: %s" % (self.ip, pduError)
            if pdu.errstat in (
                SNMP_ERR_NOACCESS,
                SNMP_ERR_RESOURCEUNAVAILABLE,
                SNMP_ERR_AUTHORIZATIONERROR,
            ):
                reactor.callLater(
                    0, d.errback, failure.Failure(SnmpError(message))
                )
                return
            else:
                result = []
                self._log.warning(message + ". OIDS: %s", oids_requested)

        reactor.callLater(0, d.callback, result)

    def _pop_requested_oids(self, pdu, response):
        try:
            return self._signSafePop(self.defers, pdu.reqid)
        except KeyError:
            # We seem to end up here if we use bad credentials with authPriv.
            # The only reasonable thing to do is call all of the deferreds with
            # Snmpv3Errors.
            for usmStatsOid, _ in response:
                usmStatsOidStr = asOidStr(usmStatsOid)

                if usmStatsOidStr == ".1.3.6.1.6.3.15.1.1.2.0":
                    # Some devices use usmStatsNotInTimeWindows as a normal
                    # part of the SNMPv3 handshake (JIRA-1565).
                    # net-snmp automatically retries the request with the
                    # previous request_id and the values for
                    # msgAuthoritativeEngineBoots and
                    # msgAuthoritativeEngineTime from this error packet.
                    self._log.debug(
                        "Received a usmStatsNotInTimeWindows error. Some "
                        "devices use usmStatsNotInTimeWindows as a normal "
                        "part of the SNMPv3 handshake."
                    )
                    raise RuntimeError("usmStatsNotInTimeWindows error")

                if usmStatsOidStr == ".1.3.6.1.2.1.1.1.0":
                    # Some devices (Cisco Nexus/MDS) use sysDescr as a normal
                    # part of the SNMPv3 handshake (JIRA-7943)
                    self._log.debug(
                        "Received sysDescr during handshake. Some devices use "
                        "sysDescr as a normal part of the SNMPv3 handshake."
                    )
                    raise RuntimeError("sysDescr during handshake")

                default_msg = "packet dropped (OID: {0})".format(
                    usmStatsOidStr
                )
                message = USM_STATS_OIDS.get(usmStatsOidStr, default_msg)
                break
            else:
                message = "packet dropped"

            for d in (
                d for d, rOids in self.defers.itervalues() if not d.called
            ):
                reactor.callLater(
                    0, d.errback, failure.Failure(Snmpv3Error(message))
                )

            raise RuntimeError(message)

    def timeout_(self, reqid):
        d = self._signSafePop(self.defers, reqid)[0]
        reactor.callLater(0, d.errback, failure.Failure(TimeoutError()))

    def _getCmdLineArgs(self):
        if not self.cmdLineArgs:
            return ()

        version = str(self.snmpVersion).lstrip("v")
        if version == "2":
            version += "c"

        agent = asAgent(self.ip, self.port)

        cmdLineArgs = list(self.cmdLineArgs) + [
            "-v",
            str(version),
            "-c",
            self.community,
            "-t",
            str(self.timeout),
            "-r",
            str(self.tries),
            agent,
        ]
        return cmdLineArgs

    def open(self):
        if self.session is not None:
            self.session.close()
            self.session = None

        if self._security:
            agent = asAgent(self.ip, self.port)
            cmdlineargs = self._security.getArguments() + (
                ("-t", str(self.timeout), "-r", str(self.tries), agent)
            )
            self.session = netsnmp.Session(
                cmdLineArgs=cmdlineargs
            )
        else:
            self.session = netsnmp.Session(
                version=netsnmp.SNMP_VERSION_MAP.get(
                    self.snmpVersion, netsnmp.SNMP_VERSION_2c
                ),
                timeout=int(self.timeout),
                retries=int(self.tries),
                peername="%s:%d" % (self.ip, self.port),
                community=self.community,
                community_len=len(self.community),
                cmdLineArgs=self._getCmdLineArgs(),
            )

        self.session.callback = self.callback
        self.session.timeout = self.timeout_
        self.session.open()
        updateReactor()

    def close(self):
        if self.session is not None:
            self.session.close()
            self.session = None
        updateReactor()

    def _get(self, oids, timeout=None, retryCount=None):
        d = defer.Deferred()
        try:
            self.defers[self.session.get(oids)] = (d, oids)
        except Exception as ex:
            return defer.fail(ex)
        updateReactor()
        return d

    def _walk(self, oid, timeout=None, retryCount=None):
        d = defer.Deferred()
        try:
            self.defers[self.session.walk(oid)] = (d, (oid,))
        except netsnmp.SnmpTimeoutError:
            return defer.fail(TimeoutError())
        except Exception as ex:
            return defer.fail(ex)
        updateReactor()
        return d

    def _getbulk(self, nonrepeaters, maxrepititions, oids):
        d = defer.Deferred()
        try:
            self.defers[
                self.session.getbulk(nonrepeaters, maxrepititions, oids)
            ] = (d, oids)
        except Exception as ex:
            return defer.fail(ex)
        updateReactor()
        return d

    def getTable(self, oids, **kw):
        try:
            t = TableRetriever(self, oids, **kw)
        except Exception as ex:
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
        if isinstance(result, (list, tuple)):
            return {asOidStr(key): value for key, value in result}
        return result


class _FakeProtocol:
    protocol = None

    def port(self):
        return self


snmpprotocol = _FakeProtocol()
