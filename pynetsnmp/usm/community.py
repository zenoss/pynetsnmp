from __future__ import absolute_import

from ..CONSTANTS import SNMP_VERSION_2c as _V2C
from .common import version_map


class Community(object):
    """
    Provides the community based security model for SNMP v1/V2c.
    """

    def __init__(self, name, version=_V2C):
        mapped = version_map.get(version)
        if mapped is None or mapped == "3":
            raise ValueError(
                "SNMP version '{}' not supported for Community".format(version)
            )
        self.name = name
        self.version = mapped

    def getArguments(self):
        community = ("-c", str(self.name)) if self.name else ()
        return ("-v", self.version) + community
