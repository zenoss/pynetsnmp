from __future__ import absolute_import

from ..CONSTANTS import (
    SNMP_VERSION_1 as _V1,
    SNMP_VERSION_2c as _V2C,
    SNMP_VERSION_3 as _V3,
)

version_map = {
    "1": "1",
    "2c": "2c",
    "3": "3",
    _V1: "1",
    _V2C: "2c",
    _V3: "3",
    "v1": "1",
    "v2c": "2c",
    "v3": "3",
}
