# Barebones code for comparing semantic version numbers
import operator

try:
    from itertools import zip_longest
except ImportError:
    from itertools import izip_longest as zip_longest  # type: ignore[attr-defined,no-redef]


class Version(object):
    __slots__ = ("atoms",)

    @classmethod
    def from_string(cls, string):
        atoms = string.split(b"." if isinstance(string, bytes) else ".")[:3]
        version = Version()
        object.__setattr__(version, "atoms", tuple(int(p) for p in atoms))
        return version

    def __init__(self, *atoms):
        object.__setattr__(self, "atoms", atoms)

    def __setattr__(self, name, value):
        raise AttributeError("Cannot set attribute {}".format(name))

    def __str__(self):
        return ".".join(str(v) for v in self.atoms)

    def __repr__(self):
        return "<Version {}>".format(".".join(str(p) for p in self.atoms))

    def __eq__(self, that):
        return all(
            a == b
            for (a, b) in zip_longest(self.atoms, that.atoms, fillvalue=0)
        )

    def __ne__(self, that):
        return not self.__eq__(that)

    def __lt__(self, that):
        return self._compare(that, operator.lt, False)

    def __le__(self, that):
        return self._compare(that, operator.lt, True)

    def __gt__(self, that):
        return self._compare(that, operator.gt, False)

    def __ge__(self, that):
        return self._compare(that, operator.gt, True)

    def _compare(self, that, op1, default):
        for a, b in zip_longest(self.atoms, that.atoms, fillvalue=0):
            if a == b:
                continue
            return op1(a, b)
        else:
            return default
