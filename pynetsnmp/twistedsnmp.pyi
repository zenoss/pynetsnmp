from typing import Any
from twisted.internet.defer import Deferred

from .errors import SnmpUsmError

class SnmpReader: ...

class AgentProxy(object):
    @classmethod
    def create(cls, address, security, timeout, retries): ...
    def __init__(
        self,
        ip,
        port,
        community,
        snmpVersion,
        protocol,
        allowCache,
        timeout,
        tries,
        cmdLineArgs,
        security,
    ): ...
    def open(self): ...
    def close(self): ...
    def callback(self, pdu): ...
    def getTable(self, oids, **kw): ...
    def get(self, oidStrs, timeout, retryCount) -> Deferred: ...
    def walk(self, oidStr, timeout, retryCount) -> Deferred: ...
    def getbulk(self, nonrepeaters, maxrepititions, oidStrs) -> Deferred: ...
    def _convertToDict(self, result) -> dict: ...

class _FakeProtocol:
    protocol: Any

    def port(self): ...

snmpprotocol: _FakeProtocol

fdMap: dict[int, SnmpReader]

__all__ = ("SnmpUsmError",)
