from __future__ import absolute_import

class _Protocol(object):
    """ """

    __slots__ = ("name",)

    def __init__(self, name):
        self.name = name

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.name == other.name

    def __str__(self):
        return self.name

    def __repr__(self):
        return "<{0.__module__}.{0.__name__} {1}>".format(
            self.__class__, self.name
        )


class _Protocols(object):
    __slots__ = ("__protocols", "__kind")

    def __init__(self, protocols, kind):
        self.__protocols = protocols
        self.__kind = kind

    def __len__(self):
        return len(self.__protocols)

    def __iter__(self):
        return iter(self.__protocols)

    def __contains__(self, proto):
        if proto not in self.__protocols:
            return any(str(p) == proto for p in self.__protocols)
        return True

    def __getitem__(self, name):
        name = str(name)
        proto = next((p for p in self.__protocols if str(p) == name), None)
        if proto is None:
            raise KeyError("No {} protocol '{}'".format(self.__kind, name))
        return proto

    def __repr__(self):
        return "<{0.__module__}.{0.__name__} {1}>".format(
            self.__class__, ", ".join(str(p) for p in self.__protocols)
        )


AUTH_MD5 = _Protocol("MD5")
AUTH_SHA = _Protocol("SHA")
AUTH_SHA_224 = _Protocol("SHA-224")
AUTH_SHA_256 = _Protocol("SHA-256")
AUTH_SHA_384 = _Protocol("SHA-384")
AUTH_SHA_512 = _Protocol("SHA-512")

auth_protocols = _Protocols(
    (
        AUTH_MD5,
        AUTH_SHA,
        AUTH_SHA_224,
        AUTH_SHA_256,
        AUTH_SHA_384,
        AUTH_SHA_512,
    ),
    "authentication",
)

PRIV_DES = _Protocol("DES")
PRIV_AES = _Protocol("AES")
PRIV_AES_192 = _Protocol("AES-192")
PRIV_AES_256 = _Protocol("AES-256")

priv_protocols = _Protocols(
    (PRIV_DES, PRIV_AES, PRIV_AES_192, PRIV_AES_256), "privacy"
)

del _Protocol
del _Protocols

__all__ = (
    "AUTH_MD5",
    "AUTH_SHA",
    "AUTH_SHA_224",
    "AUTH_SHA_256",
    "AUTH_SHA_384",
    "AUTH_SHA_512",
    "auth_protocols",
    "PRIV_DES",
    "PRIV_AES",
    "PRIV_AES_192",
    "PRIV_AES_256",
    "priv_protocols",
)
