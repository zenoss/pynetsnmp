from __future__ import absolute_import

import logging
import os
import sys

from ctypes import (
    CDLL,
    CFUNCTYPE,
    POINTER,
    RTLD_GLOBAL,
    Structure,
    Union,
    byref,
    c_char,
    c_char_p,
    c_double,
    c_float,
    c_int,
    c_int32,
    c_long,
    c_size_t,
    c_ubyte,
    c_uint,
    c_uint32,
    c_ulong,
    c_ushort,
    c_void_p,
    cast,
    create_string_buffer,
    pointer,
    sizeof,
    string_at,
)
from ctypes.util import find_library

from . import CONSTANTS
from .CONSTANTS import (
    ASN_APP_DOUBLE,
    ASN_APP_FLOAT,
    ASN_BIT_STR,
    ASN_COUNTER,
    ASN_COUNTER64,
    ASN_GAUGE,
    ASN_INTEGER,
    ASN_IPADDRESS,
    ASN_NULL,
    ASN_OBJECT_ID,
    ASN_OCTET_STR,
    ASN_TIMETICKS,
    LOG_ALERT,
    LOG_CRIT,
    LOG_DEBUG,
    LOG_EMERG,
    LOG_ERR,
    LOG_INFO,
    LOG_NOTICE,
    LOG_WARNING,
    MAX_OID_LEN,
    NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE,
    NETSNMP_CALLBACK_OP_TIMED_OUT,
    NETSNMP_DS_LIB_APPTYPE,
    NETSNMP_DS_LIBRARY_ID,
    NETSNMP_LOGHANDLER_CALLBACK,
    SNMP_CALLBACK_LIBRARY,
    SNMP_CALLBACK_LOGGING,
    SNMP_DEFAULT_COMMUNITY_LEN,
    SNMP_DEFAULT_PEERNAME,
    SNMP_DEFAULT_RETRIES,
    SNMP_DEFAULT_TIMEOUT,
    SNMP_DEFAULT_VERSION,
    SNMPERR_TIMEOUT,
    SNMP_MSG_GET,
    SNMP_MSG_GETBULK,
    SNMP_MSG_GETNEXT,
    SNMP_MSG_TRAP,
    SNMP_MSG_TRAP2,
    SNMP_SESS_UNKNOWNAUTH,
    SNMP_VERSION_1,
    SNMP_VERSION_2c,
    SNMP_VERSION_2p,
    SNMP_VERSION_2star,
    SNMP_VERSION_2u,
    SNMP_VERSION_3,
    SNMP_VERSION_sec,
    USM_AUTH_KU_LEN,
    USM_PRIV_KU_LEN,
)


def _getLogger(name):
    return logging.getLogger("zen.pynetsnmp.%s" % name)


if sys.platform.find("free") > -1:
    find_library_orig = find_library

    def find_library(name):
        for filename in [
            "/usr/lib/lib%s.so" % name,
            "/usr/local/lib/lib%s.so" % name,
        ]:
            if os.path.exists(filename):
                return filename
        return find_library_orig(name)


find_library_orig = find_library


def find_library(name):
    if sys.platform == "darwin":
        libPath = os.environ.get("DYLD_LIBRARY_PATH", "")
    else:
        libPath = os.environ.get("LD_LIBRARY_PATH", "")
    libPathList = libPath.split(":")
    for path in libPathList:
        pathName = path + "/lib%s.so" % name
        if os.path.exists(pathName):
            return pathName
    return find_library_orig(name)


oid = c_long
size_t = c_size_t
u_char = c_ubyte
u_char_p = POINTER(c_ubyte)
u_int = c_uint
u_long = c_ulong
u_short = c_ushort

try:
    # needed by newer netsnmp's
    crypto = CDLL(find_library("crypto"), RTLD_GLOBAL)
except Exception:
    import warnings

    warnings.warn("Unable to load crypto library", stacklevel=1)

lib = CDLL(find_library("netsnmp"), RTLD_GLOBAL)
lib.netsnmp_get_version.restype = c_char_p

version = lib.netsnmp_get_version()
float_version = float(".".join(version.split(".")[:2]))
_netsnmp_str_version = tuple(str(v) for v in version.split("."))

if float_version < 5.099:
    raise ImportError("netsnmp version 5.1 or greater is required")


class netsnmp_session(Structure):
    pass


class netsnmp_pdu(Structure):
    pass


class netsnmp_transport(Structure):
    pass


# include/net-snmp/types.h
class netsnmp_trap_stats(Structure):
    _fields_ = [
        ("sent_count", c_ulong),
        ("sent_last_sent", c_ulong),
        ("sent_fail_count", c_ulong),
        ("sent_last_fail", c_ulong),
        ("ack_count", c_ulong),
        ("ack_last_rcvd", c_ulong),
        ("sec_err_count", c_ulong),
        ("sec_err_last", c_ulong),
        ("timeouts", c_ulong),
        ("sent_last_timeout", c_ulong),
    ]


authenticator = CFUNCTYPE(
    u_char_p, u_char_p, POINTER(c_size_t), u_char_p, c_size_t
)


# include/net-snmp/types.h
# int (*netsnmp_callback) (int, netsnmp_session *, int, netsnmp_pdu *, void *);
# the first argument is the return type in CFUNCTYPE notation.
netsnmp_callback = CFUNCTYPE(
    c_int,
    c_int,
    POINTER(netsnmp_session),
    c_int,
    POINTER(netsnmp_pdu),
    c_void_p,
)

# int (*proc)(int, char * const *, int)
arg_parse_proc = CFUNCTYPE(c_int, POINTER(c_char_p), c_int)

localname = []
paramName = []
transportConfig = []
trapStats = []
msgMaxSize = []
baseTransport = []
fOpen = []
fConfig = []
fCopy = []
fSetupSession = []
identifier = []
fGetTaddr = []

if float_version > 5.199:
    localname = [("localname", c_char_p)]
    if float_version > 5.299:
        paramName = [("paramName", c_char_p)]
if _netsnmp_str_version >= ("5", "6"):
    # Versions >= 5.6 and < 5.6.1.1 broke binary compatibility and changed
    # oid type from c_long to c_uint32. This works around the issue for these
    # platforms to allow things to work properly.
    if _netsnmp_str_version <= ("5", "6", "1", "1"):
        oid = c_uint32

    # Versions >= 5.6 broke binary compatibility by adding transport
    # specific configuration.
    class netsnmp_container_s(Structure):
        pass

    transportConfig = [
        ("transport_configuration", POINTER(netsnmp_container_s))
    ]
if _netsnmp_str_version >= ("5", "8"):
    # Version >= 5.8 broke binary compatibility, adding the trap_stats
    # member to the netsnmp_session struct
    trapStats = [("trap_stats", POINTER(netsnmp_trap_stats))]
    # Version >= 5.8 broke binary compatibility, adding the msgMaxSize
    # member to the snmp_pdu struct
    msgMaxSize = [("msgMaxSize", c_long)]
    baseTransport = [("base_transport", POINTER(netsnmp_transport))]
    fOpen = [("f_open", c_void_p)]
    fConfig = [("f_config", c_void_p)]
    fCopy = [("f_copy", c_void_p)]
    fSetupSession = [("f_setup_session", c_void_p)]
    identifier = [("identifier", POINTER(u_char_p))]
    fGetTaddr = [("f_get_taddr", c_void_p)]
    # Version >= 5.8 broke binary compatibility, doubling the size of these
    # constants used for struct sizes
    USM_AUTH_KU_LEN = 64
    USM_PRIV_KU_LEN = 64


SNMP_VERSION_MAP = {
    "v1": SNMP_VERSION_1,
    "v2c": SNMP_VERSION_2c,
    "v2u": SNMP_VERSION_2u,
    "v3": SNMP_VERSION_3,
    "sec": SNMP_VERSION_sec,
    "2p": SNMP_VERSION_2p,
    "2star": SNMP_VERSION_2star,
}


# include/net-snmp/types.h
netsnmp_session._fields_ = (
    [
        ("version", c_long),
        ("retries", c_int),
        ("timeout", c_long),
        ("flags", u_long),
        ("subsession", POINTER(netsnmp_session)),
        ("next", POINTER(netsnmp_session)),
        ("peername", c_char_p),
        ("remote_port", u_short),  # deprecated
    ]
    + localname
    + [
        ("local_port", u_short),
        ("authenticator", authenticator),
        ("callback", netsnmp_callback),
        ("callback_magic", c_void_p),
        ("s_errno", c_int),
        ("s_snmp_errno", c_int),
        ("sessid", c_long),
        ("community", u_char_p),
        ("community_len", size_t),
        ("rcvMsgMaxSize", size_t),
        ("sndMsgMaxSize", size_t),
        ("isAuthoritative", u_char),
        ("contextEngineID", u_char_p),
        ("contextEngineIDLen", size_t),
        ("engineBoots", u_int),
        ("engineTime", u_int),
        ("contextName", c_char_p),
        ("contextNameLen", size_t),
        ("securityEngineID", u_char_p),
        ("securityEngineIDLen", size_t),
        ("securityName", c_char_p),
        ("securityNameLen", size_t),
        ("securityAuthProto", POINTER(oid)),
        ("securityAuthProtoLen", size_t),
        ("securityAuthKey", u_char * USM_AUTH_KU_LEN),
        ("securityAuthKeyLen", c_size_t),
        ("securityAuthLocalKey", c_char_p),
        ("securityAuthLocalKeyLen", c_size_t),
        ("securityPrivProto", POINTER(oid)),
        ("securityPrivProtoLen", c_size_t),
        ("securityPrivKey", c_char * USM_PRIV_KU_LEN),
        ("securityPrivKeyLen", c_size_t),
        ("securityPrivLocalKey", c_char_p),
        ("securityPrivLocalKeyLen", c_size_t),
        ("securityModel", c_int),
        ("securityLevel", c_int),
    ]
    + paramName
    + trapStats
    + [
        ("securityInfo", c_void_p),
    ]
    + transportConfig
    + [
        ("myvoid", c_void_p),
    ]
)


dataFreeHook = CFUNCTYPE(c_void_p)


class counter64(Structure):
    _fields_ = [
        ("high", c_ulong),
        ("low", c_ulong),
    ]


# include/net-snmp/types.h
class netsnmp_vardata(Union):
    _fields_ = [
        ("integer", POINTER(c_long)),
        ("string", c_char_p),
        ("objid", POINTER(oid)),
        ("bitstring", POINTER(c_ubyte)),
        ("counter64", POINTER(counter64)),
        ("floatVal", POINTER(c_float)),
        ("doubleVal", POINTER(c_double)),
    ]


class netsnmp_variable_list(Structure):
    pass


# include/net-snmp/types.h
netsnmp_variable_list._fields_ = [
    ("next_variable", POINTER(netsnmp_variable_list)),
    ("name", POINTER(oid)),
    ("name_length", c_size_t),
    ("type", c_char),
    ("val", netsnmp_vardata),
    ("val_len", c_size_t),
    ("name_loc", oid * MAX_OID_LEN),
    ("buf", c_char * 40),
    ("data", c_void_p),
    ("dataFreeHook", dataFreeHook),
    ("index", c_int),
]
# include/net-snmp/types.h
netsnmp_pdu._fields_ = (
    [
        ("version", c_long),
        ("command", c_int),
        ("reqid", c_long),
        ("msgid", c_long),
        ("transid", c_long),
        ("sessid", c_long),
        ("errstat", c_long),
        ("errindex", c_long),
        ("time", c_ulong),
        ("flags", c_ulong),
        ("securityModel", c_int),
        ("securityLevel", c_int),
        ("msgParseModel", c_int),
    ]
    + msgMaxSize
    + [
        ("transport_data", c_void_p),
        ("transport_data_length", c_int),
        ("tDomain", POINTER(oid)),
        ("tDomainLen", c_size_t),
        ("variables", POINTER(netsnmp_variable_list)),
        ("community", c_char_p),
        ("community_len", c_size_t),
        ("enterprise", POINTER(oid)),
        ("enterprise_length", c_size_t),
        ("trap_type", c_long),
        ("specific_type", c_long),
        ("agent_addr", c_ubyte * 4),
        ("contextEngineID", c_char_p),
        ("contextEngineIDLen", c_size_t),
        ("contextName", c_char_p),
        ("contextNameLen", c_size_t),
        ("securityEngineID", c_char_p),
        ("securityEngineIDLen", c_size_t),
        ("securityName", c_char_p),
        ("securityNameLen", c_size_t),
        ("priority", c_int),
        ("range_subid", c_int),
        ("securityStateRef", c_void_p),
    ]
)

netsnmp_pdu_p = POINTER(netsnmp_pdu)


# Redirect netsnmp logging to our log
class netsnmp_log_message(Structure):
    pass


netsnmp_log_message_p = POINTER(netsnmp_log_message)

# callback.h
# typedef int (SNMPCallback) (
#     int majorID, int minorID, void *serverarg, void *clientarg);
log_callback = CFUNCTYPE(c_int, c_int, netsnmp_log_message_p, c_void_p)

# include/net-snmp/library/snmp_logging.h
netsnmp_log_message._fields_ = [
    ("priority", c_int),
    ("msg", c_char_p),
]
PRIORITY_MAP = {
    LOG_EMERG: logging.CRITICAL,
    LOG_ALERT: logging.CRITICAL,
    LOG_CRIT: logging.CRITICAL,
    LOG_ERR: logging.ERROR,
    LOG_WARNING: logging.WARNING,
    LOG_NOTICE: logging.INFO,
    LOG_INFO: logging.INFO,
    LOG_DEBUG: logging.DEBUG,
}


# snmplib/snmp_logging.c -> free(logh);
# include/net-snmp/output_api.h
# int snmp_log(int priority, const char *format, ...);
# in net-snmp -> snmp_log(LOG_ERR|WARNING|INFO|DEBUG, msg)
def netsnmp_logger(a, b, msg):
    msg = cast(msg, netsnmp_log_message_p)
    priority = PRIORITY_MAP.get(msg.contents.priority, logging.DEBUG)
    _getLogger("netsnmp").log(priority, str(msg.contents.msg).strip())
    return 0


netsnmp_logger = log_callback(netsnmp_logger)

# include/net-snmp/library/callback.h
# int snmp_register_callback(
#     int major, int minor, SNMPCallback * new_callback, void *arg);
lib.snmp_register_callback(
    SNMP_CALLBACK_LIBRARY, SNMP_CALLBACK_LOGGING, netsnmp_logger, 0
)
lib.netsnmp_register_loghandler(NETSNMP_LOGHANDLER_CALLBACK, LOG_DEBUG)
lib.snmp_pdu_create.restype = netsnmp_pdu_p
lib.snmp_open.restype = POINTER(netsnmp_session)

# include/net-snmp/library/snmp_transport.h
netsnmp_transport._fields_ = (
    [
        ("domain", POINTER(oid)),
        ("domain_length", c_int),
        ("local", u_char_p),
        ("local_length", c_int),
        ("remote", u_char_p),
        ("remote_length", c_int),
        ("sock", c_int),
        ("flags", u_int),
        ("data", c_void_p),
        ("data_length", c_int),
        ("msgMaxSize", c_size_t),
    ]
    + baseTransport
    + [
        ("f_recv", c_void_p),
        ("f_send", c_void_p),
        ("f_close", c_void_p),
    ]
    + fOpen
    + [
        ("f_accept", c_void_p),
        ("f_fmtaddr", c_void_p),
    ]
    + fCopy
    + fCopy
    + fSetupSession
    + identifier
    + fGetTaddr
)

# include/net-snmp/library/snmp_transport.h
# netsnmp_transport *netsnmp_tdomain_transport(
#     const char *str, int local, const char *default_domain);
lib.netsnmp_tdomain_transport.restype = POINTER(netsnmp_transport)

# include/net-snmp/library/snmp_api.h
# netsnmp_session *snmp_add(
#     netsnmp_session *,
#     struct netsnmp_transport_s *,
#     int (*fpre_parse) (
#         netsnmp_session *, struct netsnmp_transport_s *, void *, int),
#     int (*fpost_parse) (netsnmp_session *, netsnmp_pdu *, int)
# );
lib.snmp_add.restype = POINTER(netsnmp_session)

# include/net-snmp/session_api.h
# int snmp_add_var(netsnmp_pdu *, const oid *, size_t, char, const char *);
lib.snmp_add_var.argtypes = [
    netsnmp_pdu_p,
    POINTER(oid),
    c_size_t,
    c_char,
    c_char_p,
]

lib.get_uptime.restype = c_long

# include/net-snmp/session_api.h
# int snmp_send(netsnmp_session *, netsnmp_pdu *);
lib.snmp_send.argtypes = (POINTER(netsnmp_session), netsnmp_pdu_p)
lib.snmp_send.restype = c_int


# A pointer to a _CallbackData struct is used for the callback_magic
# parameter on the netsnmp_session structure.  In the case of a SNMP v3
# authentication error, a portion of the data pointed by callback_magic
# is overwritten.  The 'reserved' member of the _CallbackData struct
# allocates enough space for the net-snmp library to write into without
# corrupting the rest of the struct.
class _CallbackData(Structure):
    _fields_ = [
        ("reserved", c_void_p),  # net-snmp corrupts this on snmpv3 auth errors
        ("session_id", c_ulong),
    ]


_CallbackDataPtr = POINTER(_CallbackData)

lib.snmpv3_get_report_type.argtypes = [netsnmp_pdu_p]
lib.snmpv3_get_report_type.restype = c_int

lib.snmp_api_errstring.argtypes = [c_int]
lib.snmp_api_errstring.restype = c_char_p


class UnknownType(Exception):
    pass


def mkoid(n):
    oids = (oid * len(n))()
    for i, v in enumerate(n):
        oids[i] = v
    return oids


def strToOid(oidStr):
    return mkoid(tuple([int(x) for x in oidStr.strip(".").split(".")]))


def decodeOid(pdu):
    return tuple(
        [pdu.val.objid[i] for i in range(pdu.val_len / sizeof(u_long))]
    )


def decodeIp(pdu):
    return ".".join(map(str, pdu.val.bitstring[:4]))


def decodeBigInt(pdu):
    int64 = pdu.val.counter64.contents
    return (int64.high << 32) + int64.low


def decodeString(pdu):
    if pdu.val_len:
        return string_at(pdu.val.bitstring, pdu.val_len)
    return ""


_valueToConstant = {
    chr(_v): _k
    for _k, _v in CONSTANTS.__dict__.items()
    if isinstance(_v, int) and (0 <= _v < 256)
}


decoder = {
    chr(ASN_OCTET_STR): decodeString,
    # chr(ASN_BOOLEAN): lambda pdu: pdu.val.integer.contents.value,
    chr(ASN_INTEGER): lambda pdu: pdu.val.integer.contents.value,
    chr(ASN_NULL): lambda pdu: None,
    chr(ASN_OBJECT_ID): decodeOid,
    chr(ASN_BIT_STR): decodeString,
    chr(ASN_IPADDRESS): decodeIp,
    chr(ASN_COUNTER): lambda pdu: pdu.val.integer.contents.value,
    chr(ASN_GAUGE): lambda pdu: pdu.val.integer.contents.value,
    chr(ASN_TIMETICKS): lambda pdu: pdu.val.integer.contents.value,
    chr(ASN_COUNTER64): decodeBigInt,
    chr(ASN_APP_FLOAT): lambda pdu: pdu.val.float.contents.value,
    chr(ASN_APP_DOUBLE): lambda pdu: pdu.val.double.contents.value,
}


def decodeType(var, log):
    oid = [var.name[i] for i in range(var.name_length)]
    decode = decoder.get(var.type, None)
    if not decode:
        # raise UnknownType(oid, ord(var.type))
        log_oid = ".".join(map(str, oid))
        log.debug(
            "No decoder for oid %s type %s - returning None",
            log_oid,
            _valueToConstant.get(var.type, var.type),
        )
        return (oid, None)
    return oid, decode(var)


def getResult(pdu, log):
    result = []
    var = pdu.variables
    while var:
        var = var.contents
        oid, val = decodeType(var, log)
        result.append((tuple(oid), val))
        var = var.next_variable
    return result


class SnmpError(Exception):
    def __init__(self, why):
        lib.snmp_perror(why)
        Exception.__init__(self, why)


class SnmpTimeoutError(Exception):
    pass


sessionMap = {}


def _callback(operation, sp, reqid, pdu, magic):
    data_ptr = cast(magic, _CallbackDataPtr)
    sess = sessionMap[data_ptr.contents.session_id]
    try:
        if operation == NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE:
            sess.callback(pdu.contents)
        elif operation == NETSNMP_CALLBACK_OP_TIMED_OUT:
            sess.timeout(reqid)
        else:
            _getLogger("callback").error("Unknown operation: %d", operation)
    except Exception as ex:
        _getLogger("callback").exception("Exception in _callback %s", ex)
    return 1


_callback = netsnmp_callback(_callback)


class ArgumentParseError(Exception):
    pass


class TransportError(Exception):
    pass


def _doNothingProc(argc, argv, arg):
    return 0


_doNothingProc = arg_parse_proc(_doNothingProc)


def parse_args(args, session):
    args = [
        sys.argv[0],
    ] + args
    argc = len(args)
    argv = (c_char_p * argc)()
    for i in range(argc):
        # snmp_parse_args mutates argv, so create a copy
        argv[i] = create_string_buffer(args[i]).raw
    # WARNING: Usage of snmp_parse_args call causes memory leak.
    if lib.snmp_parse_args(argc, argv, session, "", _doNothingProc) < 0:
        raise ArgumentParseError("Unable to parse arguments", " ".join(argv))
    # keep a reference to the args for as long as sess is alive
    return argv


_NoAttribute = object()


def initialize_session(sess, cmdLineArgs, kw):
    args = None
    kw = kw.copy()
    if cmdLineArgs:
        args = _init_from_args(sess, cmdLineArgs, kw)
    else:
        lib.snmp_sess_init(byref(sess))
    for attr, value in kw.items():
        pv = getattr(sess, attr, _NoAttribute)
        if pv is _NoAttribute:
            continue  # Don't set invalid properties
        _update_session(attr, value, pv, sess)
    return args


def _init_from_args(sess, cmdLineArgs, kw):
    cmdLine = list(cmdLineArgs)
    if isinstance(cmdLine[0], tuple):
        result = []
        for opt, val in cmdLine:
            result.append(opt)
            result.append(val)
        cmdLine = result
    if kw.get("peername"):
        cmdLine.append(kw["peername"])
        del kw["peername"]
    return parse_args(cmdLine, byref(sess))


def _update_session(attr, value, pv, sess):
    if attr == "timeout":
        # -1 means 'timeout' hasn't been set
        if pv == -1:
            # Converts seconds to microseconds
            setattr(sess, attr, value * 1000000)
    elif attr == "version":
        # -1 means 'version' hasn't been set
        if pv == -1:
            setattr(sess, attr, value)
    elif attr == "community":
        # None means 'community' hasn't been set
        if pv is None:
            setattr(sess, attr, value)
            # Set 'community_len' at the same time because it's
            # related to the value for the 'community' property.
            sess.community_len = len(value)
    elif attr == "community_len":
        # Do nothing to avoid setting a 'community_len' value when no
        # value has been set for 'community', otherwise, a segmentation
        # fault can occur.
        pass
    else:
        setattr(sess, attr, value)


class Session(object):
    cb = None

    def __init__(self, cmdLineArgs=(), freeEtimelist=True, **kw):
        self.cmdLineArgs = cmdLineArgs
        self.freeEtimelist = freeEtimelist
        self.kw = kw
        self.sess = None
        self.args = None
        self._data = None  # ref to _CallbackData object
        self._log = _getLogger("session")

    def _snmp_send(self, session, pdu):
        """
        Allows execution of free_etimelist() after each snmp_send() call.

        Executes lib.free_etimelist() after each lib.snmp_send() call if the
        `freeEtimelist` attribute is set, or re-calls lib.snmp_send()
        otherwise.  This frees all the memory used by entries in the
        etimelist inside the net-snmp library, allowing the processing of
        devices with duplicated engineID.

        Note: This feature is not supported by RFC.
        """

        try:
            return lib.snmp_send(session, pdu)
        finally:
            if self.freeEtimelist:
                lib.free_etimelist()

    def open(self):
        sess = netsnmp_session()
        self.args = initialize_session(sess, self.cmdLineArgs, self.kw)
        sess.callback = _callback
        self._data = _CallbackData(session_id=id(self))
        sess.callback_magic = cast(pointer(self._data), c_void_p)
        sessionMap[id(self)] = self
        self._log.debug("Client session created session_id=%s", id(self))
        ref = byref(sess)
        self.sess = lib.snmp_open(ref)
        if not self.sess:
            raise SnmpError("snmp_open")

    def awaitTraps(
        self, peername, fileno=-1, pre_parse_callback=None, debug=False
    ):
        if float_version > 5.299:
            lib.netsnmp_ds_set_string(
                NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_APPTYPE, "pynetsnmp"
            )
        if debug:
            lib.debug_register_tokens("snmp_parse")  # or "ALL" for everything
            lib.snmp_set_do_debugging(1)
        lib.netsnmp_udp_ctor()
        marker = object()
        if getattr(lib, "netsnmp_udpipv6_ctor", marker) is not marker:
            lib.netsnmp_udpipv6_ctor()
        elif getattr(lib, "netsnmp_udp6_ctor", marker) is not marker:
            lib.netsnmp_udp6_ctor()
        else:
            self._log.debug(
                "Cannot find constructor function for UDP/IPv6 transport "
                "domain object."
            )
        lib.init_snmp("zenoss_app")
        lib.setup_engineID(None, None)
        transport = lib.netsnmp_tdomain_transport(peername, 1, "udp")
        if not transport:
            raise SnmpError(
                "Unable to create transport {peername}".format(
                    peername=peername
                )
            )
        if fileno >= 0:
            os.dup2(fileno, transport.contents.sock)

        sess = netsnmp_session()
        self.sess = pointer(sess)
        lib.snmp_sess_init(self.sess)
        sess.peername = SNMP_DEFAULT_PEERNAME
        sess.version = SNMP_DEFAULT_VERSION
        sess.community_len = SNMP_DEFAULT_COMMUNITY_LEN
        sess.retries = SNMP_DEFAULT_RETRIES
        sess.timeout = SNMP_DEFAULT_TIMEOUT
        sess.callback = _callback

        self._data = _CallbackData(session_id=id(self))
        sess.callback_magic = cast(pointer(self._data), c_void_p)
        sessionMap[id(self)] = self
        self._log.debug("Server session created session_id=%s", id(self))

        # sess.authenticator = None
        sess.isAuthoritative = SNMP_SESS_UNKNOWNAUTH
        rc = lib.snmp_add(self.sess, transport, pre_parse_callback, None)
        if not rc:
            raise SnmpError("snmp_add")

    def create_users(self, users):
        self._log.debug("create_users: Creating %s users.", len(users))
        for user in users:
            if user.version == 3:
                try:
                    line = ""
                    if user.engine_id:
                        line = "-e {} ".format(user.engine_id)
                    line += " ".join(
                        [
                            user.username,
                            user.authentication_type,  # MD5 or SHA
                            user.authentication_passphrase,
                            user.privacy_protocol,  # DES or AES
                            user.privacy_passphrase,
                        ]
                    )
                    lib.usm_parse_create_usmUser("createUser", line)
                    self._log.debug("create_users: created user: %s", user)
                except Exception as e:
                    self._log.debug(
                        "create_users: could not create user: %s: (%s: %s)",
                        user,
                        e.__class__.__name__,
                        e,
                    )

    def sendTrap(self, trapoid, varbinds=None):
        if "-v1" in self.cmdLineArgs:
            pdu = lib.snmp_pdu_create(SNMP_MSG_TRAP)
            if hasattr(self, "agent_addr"):
                # pdu.contents is a netsnmp_pdu, defined above, therefore its
                # fields are c types.
                # self.agent_addr is an ipv4 address, and the v1 trap wants
                # a c array of 4 unsigned bytes, so chop it up, make the
                # octets ints, then a bytearray from that will cast.
                pdu.contents.agent_addr = (c_ubyte * 4)(
                    *(bytearray([int(x) for x in self.agent_addr.split(".")]))
                )
            pdu.contents.trap_type = 6
            pdu.contents.specific_type = 0
            pdu.contents.time = lib.get_uptime()

        else:
            pdu = lib.snmp_pdu_create(SNMP_MSG_TRAP2)

            # sysUpTime is mandatory on V2Traps.
            objid_sysuptime = mkoid((1, 3, 6, 1, 2, 1, 1, 3, 0))
            uptime = "%ld" % lib.get_uptime()
            lib.snmp_add_var(
                pdu, objid_sysuptime, len(objid_sysuptime), "t", uptime
            )

        # snmpTrapOID is mandatory on V2Traps.
        objid_snmptrap = mkoid((1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0))
        lib.snmp_add_var(
            pdu, objid_snmptrap, len(objid_snmptrap), "o", trapoid
        )

        if varbinds:
            for n, t, v in varbinds:
                n = strToOid(n)
                lib.snmp_add_var(pdu, n, len(n), t, v)

        self._snmp_send(self.sess, pdu)

    def close(self):
        if self.sess is not None:
            lib.snmp_close(self.sess)
            self.sess = None
            self.args = None
            self._data = None
        if id(self) not in sessionMap:
            self._log.warn(
                "Session ID not found session_id=%s %r",
                id(self),
                self.kw,
            )
            return
        del sessionMap[id(self)]
        self._log.debug("Session closed session_id=%s", id(self))

    def callback(self, pdu):
        pass

    def timeout(self, reqid):
        pass

    def _create_request(self, packetType):
        return lib.snmp_pdu_create(packetType)

    def sget(self, oids):
        req = self._create_request(SNMP_MSG_GET)
        for oid in oids:
            oid = mkoid(oid)
            lib.snmp_add_null_var(req, oid, len(oid))
        response = netsnmp_pdu_p()
        if lib.snmp_synch_response(self.sess, req, byref(response)) == 0:
            result = dict(getResult(response.contents, self._log))
            lib.snmp_free_pdu(response)
            return result

    def _handle_send_status(self, req, send_status, send_type):
        if send_status == 0:
            cliberr = c_int()
            snmperr = c_int()
            errstring = c_char_p()
            lib.snmp_error(
                self.sess, byref(cliberr), byref(snmperr), byref(errstring)
            )
            msg_fmt = "%s: snmp_send cliberr=%s, snmperr=%s, errstring=%s"
            msg_args = (
                send_type,
                cliberr.value,
                snmperr.value,
                errstring.value,
            )
            self._log.debug(msg_fmt, *msg_args)
            lib.snmp_free_pdu(req)
            if snmperr.value == SNMPERR_TIMEOUT:
                raise SnmpTimeoutError()
            raise SnmpError(msg_fmt % msg_args)

    def get(self, oids):
        req = self._create_request(SNMP_MSG_GET)
        for oid in oids:
            oid = mkoid(oid)
            lib.snmp_add_null_var(req, oid, len(oid))
        send_status = self._snmp_send(self.sess, req)
        self._handle_send_status(req, send_status, "get")
        return req.contents.reqid

    def getbulk(self, nonrepeaters, maxrepetitions, oids):
        req = self._create_request(SNMP_MSG_GETBULK)
        req = cast(req, POINTER(netsnmp_pdu))
        req.contents.errstat = nonrepeaters
        req.contents.errindex = maxrepetitions
        for oid in oids:
            oid = mkoid(oid)
            lib.snmp_add_null_var(req, oid, len(oid))
        send_status = self._snmp_send(self.sess, req)
        self._handle_send_status(req, send_status, "get")
        return req.contents.reqid

    def walk(self, root):
        req = self._create_request(SNMP_MSG_GETNEXT)
        oid = mkoid(root)
        lib.snmp_add_null_var(req, oid, len(oid))
        send_status = self._snmp_send(self.sess, req)
        self._log.debug("walk: send_status=%s", send_status)
        self._handle_send_status(req, send_status, "walk")
        return req.contents.reqid


MAXFD = 1024
FD_SETSIZE = MAXFD
fdset = c_int32 * (MAXFD / 32)


class timeval(Structure):
    _fields_ = [
        ("tv_sec", c_long),
        ("tv_usec", c_long),
    ]


def fdset2list(rd, n):
    result = []
    for i in range(len(rd)):
        if rd[i]:
            for j in range(0, 32):
                bit = 0x00000001 << (j % 32)
                if rd[i] & bit:
                    result.append(i * 32 + j)
    return result


class netsnmp_large_fd_set(Structure):
    # This structure must be initialized by calling netsnmp_large_fd_set_init()
    # and must be cleaned up via netsnmp_large_fd_set_cleanup(). If this last
    # function is not called this may result in a memory leak.

    _fields_ = [
        ("lfs_setsize", c_uint),
        ("lfs_setptr", POINTER(fdset)),
        ("lfs_set", fdset),
    ]


def snmp_select_info():
    rd = fdset()
    maxfd = c_int(0)
    timeout = timeval()
    timeout.tv_sec = 1
    timeout.tv_usec = 0
    block = c_int(0)
    maxfd = c_int(MAXFD)
    lib.snmp_select_info(byref(maxfd), byref(rd), byref(timeout), byref(block))
    t = None
    if not block:
        t = timeout.tv_sec + timeout.tv_usec / 1e6
    return fdset2list(rd, maxfd.value), t


def snmp_select_info2():
    rd = netsnmp_large_fd_set()
    lib.netsnmp_large_fd_set_init(byref(rd), FD_SETSIZE)
    maxfd = c_int(0)
    timeout = timeval()
    timeout.tv_sec = 1
    timeout.tv_usec = 0
    block = c_int(0)
    maxfd = c_int(MAXFD)
    lib.snmp_select_info2(
        byref(maxfd), byref(rd), byref(timeout), byref(block)
    )
    t = None
    if not block:
        t = timeout.tv_sec + timeout.tv_usec / 1e6

    result = []
    for fd in range(0, maxfd.value + 1):
        if lib.netsnmp_large_fd_is_set(fd, byref(rd)):
            result.append(fd)

    lib.netsnmp_large_fd_set_cleanup(byref(rd))
    return result, t


def snmp_read(fd):
    rd = fdset()
    rd[fd / 32] |= 1 << (fd % 32)
    lib.snmp_read(byref(rd))


def snmp_read2(fd):
    rd = netsnmp_large_fd_set()
    lib.netsnmp_large_fd_set_init(byref(rd), FD_SETSIZE)
    lib.netsnmp_large_fd_setfd(fd, byref(rd))
    lib.snmp_read2(byref(rd))
    lib.netsnmp_large_fd_set_cleanup(byref(rd))


done = False


def loop():
    while not done:
        from select import select

        rd, t = snmp_select_info()
        if t is None:
            break
        rd, w, x = select(rd, [], [], t)
        if rd:
            for r in rd:
                snmp_read(r)
        else:
            lib.snmp_timeout()


def stop():
    global done
    done = 1
