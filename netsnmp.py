import os
from ctypes import *
from ctypes.util import find_library
from CONSTANTS import *

# freebsd cannot manage a decent find_library
import sys
if sys.platform.find('free') > -1:
    find_library_orig = find_library
    def find_library(name):
        for name in ['/usr/lib/lib%s.so' % name,
                     '/usr/local/lib/lib%s.so' % name]:
            if os.path.exists(name):
                return name
        return find_library_orig(name)
    
import logging
log = logging.getLogger('netsnmp')

c_int_p = c_void_p
authenticator = CFUNCTYPE(c_char_p, c_int_p, c_char_p, c_int)

try:
    # needed by newer netsnmp's
    crypto = CDLL(find_library('crypto'), RTLD_GLOBAL)
except Exception:
    import warnings
    warnings.warn("Unable to load crypto library")

lib = CDLL(find_library('netsnmp'))
lib.netsnmp_get_version.restype = c_char_p

oid = c_long
u_long = c_ulong
u_short = c_ushort
u_char_p = c_char_p
u_int = c_uint
size_t = c_size_t
u_char = c_byte

class netsnmp_session(Structure): pass
class netsnmp_pdu(Structure): pass

# int (*netsnmp_callback) (int, netsnmp_session *, int, netsnmp_pdu *, void *);
netsnmp_callback = CFUNCTYPE(c_int,
                             c_int, POINTER(netsnmp_session),
                             c_int, POINTER(netsnmp_pdu),
                             c_void_p)

version = lib.netsnmp_get_version()
float_version = float('.'.join(version.split('.')[:2]))
localname = []
paramName = []
if float_version < 5.099:
    raise ImportError("netsnmp version 5.1 or greater is required")
if float_version > 5.199:
    localname = [('localname', c_char_p)]
    if float_version > 5.299:
        paramName = [('paramName', c_char_p)]

netsnmp_session._fields_ = [
        ('version', c_long),
        ('retries', c_int),
        ('timeout', c_long),
        ('flags', u_long),
        ('subsession', POINTER(netsnmp_session)),
        ('next', POINTER(netsnmp_session)),
        ('peername', c_char_p),
        ('remote_port', u_short), ] + localname + [
        ('local_port', u_short),
        ('authenticator', authenticator),
        ('callback', netsnmp_callback),
        ('callback_magic', c_void_p),
        ('s_errno', c_int),
        ('s_snmp_errno', c_int),
        ('sessid', c_long),
        ('community', u_char_p),
        ('community_len', size_t),
        ('rcvMsgMaxSize', size_t),
        ('sndMsgMaxSize', size_t),
        
        ('isAuthoritative', u_char),
        ('contextEngineID', u_char_p),
        ('contextEngineIDLen', size_t),
        ('engineBoots', u_int),
        ('engineTime', u_int),
        ('contextName', c_char_p),
        ('contextNameLen', size_t),
        ('securityEngineID', u_char_p),
        ('securityEngineIDLen', size_t),
        ('securityName', c_char_p),
        ('securityNameLen', size_t),
        
        ('securityAuthProto', POINTER(oid)),
        ('securityAuthProtoLen', size_t),
        ('securityAuthKey', u_char * USM_AUTH_KU_LEN),
        ('securityAuthKeyLen', c_size_t),
        ('securityAuthLocalKey', c_char_p),
        ('securityAuthLocalKeyLen', c_size_t),

        ('securityPrivProto', POINTER(oid)),
        ('securityPrivProtoLen', c_size_t),
        ('securityPrivKey', c_char * USM_PRIV_KU_LEN),
        ('securityPrivKeyLen', c_size_t),
        ('securityPrivLocalKey', c_char_p),
        ('securityPrivLocalKeyLen', c_size_t),

        ] + paramName + [

        ('securityModel', c_int),
        ('securityLevel', c_int),

        ('securityInfo', c_void_p),

        ('myvoid', c_void_p),
        ]


dataFreeHook = CFUNCTYPE(c_void_p)

class counter64(Structure):
    _fields_ = [
        ('high', c_ulong),
        ('low', c_ulong),
        ]

class netsnmp_vardata(Union):
    _fields_ = [
        ('integer', POINTER(c_long)),
        ('uinteger', POINTER(c_ulong)),
        ('string', c_char_p),
        ('objid', POINTER(oid)),
        ('bitstring', POINTER(c_ubyte)),
        ('counter64', POINTER(counter64)),
        ('floatVal', POINTER(c_float)),
        ('doubleVal', POINTER(c_double)),
        ]    

class netsnmp_variable_list(Structure):
    pass
netsnmp_variable_list._fields_ = [
        ('next_variable', POINTER(netsnmp_variable_list)),
        ('name', POINTER(oid)),
        ('name_length', c_size_t),
        ('type', c_char),
        ('val', netsnmp_vardata),
        ('val_len', c_size_t),
        ('name_loc', oid * MAX_OID_LEN),
        ('buf', c_char * 40),
        ('data', c_void_p),
        ('dataFreeHook', dataFreeHook),
        ('index', c_int),
        ]
    
netsnmp_pdu._fields_ = [
        ('version', c_long ),
        ('command', c_int ),
        ('reqid', c_long ),
        ('msgid', c_long ),
        ('transid', c_long ),
        ('sessid', c_long ),
        ('errstat', c_long ),
        ('errindex', c_long ),
        ('time', c_ulong ),
        ('flags', c_ulong ),
        ('securityModel', c_int ),
        ('securityLevel', c_int ),
        ('msgParseModel', c_int ),
        ('transport_data', c_void_p),
        ('transport_data_length', c_int ),
        ('tDomain', POINTER(oid)),
        ('tDomainLen', c_size_t ),
        ('variables', POINTER(netsnmp_variable_list)),
        ('community', c_char_p),
        ('community_len', c_size_t ),
        ('enterprise', POINTER(oid)),
        ('enterprise_length', c_size_t ),
        ('trap_type', c_long ),
        ('specific_type', c_long ),
        ('agent_addr', c_char * 4),
        ('contextEngineID', c_char_p ),
        ('contextEngineIDLen', c_size_t ),
        ('contextName', c_char_p),
        ('contextNameLen', c_size_t ),
        ('securityEngineID', c_char_p),
        ('securityEngineIDLen', c_size_t ),
        ('securityName', c_char_p),
        ('securityNameLen', c_size_t ),
        ('priority', c_int ),
        ('range_subid', c_int ),
        ('securityStateRef', c_void_p),
        ]

netsnmp_pdu_p = POINTER(netsnmp_pdu)

# Redirect netsnmp logging to our log 
class netsnmp_log_message(Structure): pass
netsnmp_log_message_p = POINTER(netsnmp_log_message)
log_callback = CFUNCTYPE(c_int, c_int,
                         netsnmp_log_message_p,
                         c_void_p);
netsnmp_log_message._fields_ = [
    ('priority', c_int),
    ('msg', c_char_p),
]
PRIORITY_MAP = {
    LOG_EMERG     : logging.CRITICAL + 2,
    LOG_ALERT     : logging.CRITICAL + 1,
    LOG_CRIT      : logging.CRITICAL,
    LOG_ERR       : logging.ERROR,
    LOG_WARNING   : logging.WARNING,
    LOG_NOTICE    : logging.INFO + 1,
    LOG_INFO      : logging.INFO,
    LOG_DEBUG     : logging.DEBUG,
    }
def netsnmp_logger(a, b, msg):
    msg = cast(msg, netsnmp_log_message_p)
    priority = PRIORITY_MAP.get(msg.contents.priority, logging.WARNING)
    log.log(priority, msg.contents.msg)
    return 0
netsnmp_logger = log_callback(netsnmp_logger)
lib.snmp_register_callback(SNMP_CALLBACK_LIBRARY,
                           SNMP_CALLBACK_LOGGING,
                           netsnmp_logger,
                           0)
lib.netsnmp_register_loghandler(NETSNMP_LOGHANDLER_CALLBACK, LOG_DEBUG)
lib.snmp_pdu_create.restype = netsnmp_pdu_p
lib.snmp_open.restype = POINTER(netsnmp_session)

class UnknownType(Exception):
    pass

def mkoid(n):
    oids = (oid * len(n))()
    for i, v in enumerate(n):
        oids[i] = v
    return oids

def decodeOid(pdu):
    return tuple([pdu.val.objid[i] for i in range(pdu.val_len / sizeof(u_long))])

def decodeIp(pdu):
    return '.'.join(map(str, pdu.val.bitstring[:4]))

def decodeBigInt(pdu):
    int64 = pdu.val.counter64.contents
    return (int64.high << 32L) + int64.low

def decodeString(pdu):
    if pdu.val_len:
        return string_at(pdu.val.bitstring, pdu.val_len)
    return ''

decoder = {
    chr(ASN_OCTET_STR): decodeString,
    # chr(ASN_BOOLEAN): lambda pdu: pdu.val.integer.contents.value,
    chr(ASN_INTEGER): lambda pdu: pdu.val.integer.contents.value,
    chr(ASN_NULL): lambda pdu: None,
    chr(ASN_OBJECT_ID): decodeOid,
    chr(ASN_BIT_STR): decodeString,
    chr(ASN_IPADDRESS): decodeIp,
    chr(ASN_COUNTER): lambda pdu: pdu.val.uinteger.contents.value,
    chr(ASN_GAUGE): lambda pdu: pdu.val.integer.contents.value,
    chr(ASN_TIMETICKS): lambda pdu: pdu.val.uinteger.contents.value,
    chr(ASN_COUNTER64): decodeBigInt,
    chr(ASN_APP_FLOAT): lambda pdu: pdu.val.float.contents.value,
    chr(ASN_APP_DOUBLE): lambda pdu: pdu.val.double.contents.value,
    }

def decodeType(var):
    oid = [var.name[i] for i in range(var.name_length)]
    decode = decoder.get(var.type, None)
    if not decode:
        # raise UnknownType(oid, ord(var.type))
        return (oid, None)
    return oid, decode(var)
    

def getResult(pdu):
    result = []
    var = pdu.variables
    while var:
        var = var.contents
        oid, val = decodeType(var)
        result.append( (tuple(oid), val) )
        var = var.next_variable
    return result

class SnmpError(Exception):

    def __init__(self, why):
        lib.snmp_perror(why)
        Exception.__init__(self, why)

sessionMap = {}
def _callback(operation, sp, reqid, pdu, magic):
    sess = sessionMap[magic]
    try:
        if operation == NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE:
            sess.callback(pdu.contents)
        elif operation == NETSNMP_CALLBACK_OP_TIMED_OUT:
            sess.timeout(reqid)
        else:
            log.error("Unknown operation: %d", operation)
    except Exception, ex:
        log.exception("Exception in _callback %s", ex)
    return 1
_callback = netsnmp_callback(_callback)

class Session(object):

    cb = None

    def __init__(self, **kw):
        self.kw = kw
        self.sess = None

    def open(self):
        sess = netsnmp_session()
        lib.snmp_sess_init(byref(sess))
        for attr, value in self.kw.items():
            setattr(sess, attr, value)
        sess.callback = _callback
        sess.callback_magic = id(self)
        sess = lib.snmp_open(byref(sess))
        self.sess = sess # cast(sess, POINTER(netsnmp_session))
        if not self.sess:
            raise SnmpError('snmp_open')
        sessionMap[id(self)] = self

    def close(self):
        if not self.sess: return
        if id(self) not in sessionMap:
            log.warn("Unable to find session id %r in sessionMap", self.kw)
            return
        lib.snmp_close(self.sess)
        del sessionMap[id(self)]

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
            result = dict(getResult(response.contents))
            lib.snmp_free_pdu(response)
            return result


    def get(self, oids):
        req = self._create_request(SNMP_MSG_GET)
        for oid in oids:
            oid = mkoid(oid)
            lib.snmp_add_null_var(req, oid, len(oid))
        if not lib.snmp_send(self.sess, req):
            lib.snmp_free_pdu(req)
            raise SnmpError("snmp_send")
        return req.contents.reqid

    def getbulk(self, nonrepeaters, maxrepetitions, oids):
        req = self._create_request(SNMP_MSG_GETBULK)
        req = cast(req, POINTER(netsnmp_pdu))
        req.contents.errstat = nonrepeaters
        req.contents.errindex = maxrepetitions
        for oid in oids:
            oid = mkoid(oid)
            lib.snmp_add_null_var(req, oid, len(oid))
        if not lib.snmp_send(self.sess, req):
            lib.snmp_free_pdu(req)
            raise SnmpError("snmp_send")
        return req.contents.reqid

    def walk(self, root):
        req = self._create_request(SNMP_MSG_GETNEXT)
        oid = mkoid(root)
        lib.snmp_add_null_var(req, oid, len(oid))
        if not lib.snmp_send(self.sess, req):
            lib.snmp_free_pdu(req)
            raise SnmpError("snmp_send")
        return req.contents.reqid

    def pdu_parse(self, pdu, buffer):
        cbuff = create_string_buffer(buffer, len(buffer))
        length = c_size_t(len(buffer))
        after_header = c_char_p()
        if lib.snmpv3_parse(byref(pdu),
                            cbuff,
                            byref(length),
                            byref(after_header),
                            self.sess):
            raise SnmpError("pdu_parse")

MAXFD = 1024
fdset = c_long * (MAXFD/32)

class timeval(Structure):
    _fields_ = [
        ('tv_sec', c_long),
        ('tv_usec', c_long),
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

def snmp_select_info():
    rd = fdset()
    maxfd = c_int(0)
    timeout = timeval()
    timeout.tv_sec = 1
    timeout.tv_usec = 0
    block = c_int(0)
    maxfd = c_int(MAXFD)
    lib.snmp_select_info(byref(maxfd),
                             byref(rd),
                             byref(timeout),
                             byref(block))
    t = None
    if not block:
        t = timeout.tv_sec + timeout.tv_usec / 1e6
    return fdset2list(rd, maxfd.value), t

def snmp_read(fd):
    rd = fdset()
    rd[fd / 32] |= 1 << (fd % 32)
    lib.snmp_read(byref(rd))

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

