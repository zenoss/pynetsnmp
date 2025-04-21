import unittest

from pynetsnmp._version import Version

class TestVersion(unittest.TestCase):

    def test_init_1(t):
        version = Version(1,2,3)
        t.assertEqual(version.atoms, (1,2,3))

    def test_init_2(t):
        version = Version(1,2)
        t.assertEqual(version.atoms, (1,2))

    def test_from_text(t):
        text = u"3.2.1"
        version = Version.from_string(text)
        t.assertEqual(version.atoms, (3, 2, 1))

    def test_from_bytes(t):
        binary = b"3.2.1"
        version = Version.from_string(binary)
        t.assertEqual(version.atoms, (3, 2, 1))

    def test_set_atoms(t):
        version = Version.from_string("3.2.1")
        with t.assertRaises(AttributeError):
            version.atoms = (5, 6, 1)

    def test_set_attribute(t):
        version = Version.from_string("3.2.1")
        with t.assertRaises(AttributeError):
            version.foo = "bar"

    def test_str(t):
        version = Version.from_string("3.2.1")
        t.assertEqual(str(version), "3.2.1")

    def test_repr(t):
        version = Version.from_string("3.2.1")
        t.assertEqual(repr(version), "<Version 3.2.1>")

    def test_equal_success(t):
        this = Version.from_string("3.2.1")
        that = Version.from_string("3.2.1")
        t.assertTrue(this == that)

    def test_equal_success_2(t):
        this = Version.from_string("3.2.0")
        that = Version.from_string("3.2")
        t.assertTrue(this == that)

    def test_equal_failure(t):
        this = Version.from_string("3.2.1")
        that_1 = Version.from_string("3.2.2")
        that_2 = Version.from_string("3.3.1")
        that_3 = Version.from_string("4.2.1")
        that_4 = Version.from_string("3.2")
        that_5 = Version.from_string("3.3")
        that_6 = Version.from_string("4")
        t.assertFalse(this == that_1)
        t.assertFalse(this == that_2)
        t.assertFalse(this == that_3)
        t.assertFalse(this == that_4)
        t.assertFalse(this == that_5)
        t.assertFalse(this == that_6)

    def test_not_equal_success(t):
        version1 = Version.from_string("3.2.1")
        version2_1 = Version.from_string("3.2.2")
        version2_2 = Version.from_string("3.3.1")
        version2_3 = Version.from_string("4.2.1")
        t.assertTrue(version1 != version2_1)
        t.assertTrue(version1 != version2_2)
        t.assertTrue(version1 != version2_3)

    def test_not_equal_failure(t):
        version1 = Version.from_string("3.2.1")
        version2 = Version.from_string("3.2.1")
        t.assertFalse(version1 != version2)

    def test_less_than_success(t):
        this = Version.from_string("3.2.1")
        that1 = Version.from_string("3.2.2")
        that2 = Version.from_string("3.3.1")
        that3 = Version.from_string("4.2.1")
        t.assertTrue(this < that1)
        t.assertTrue(this < that2)
        t.assertTrue(this < that3)

    def test_less_than_failure(t):
        this = Version.from_string("3.2.1")
        that1 = Version.from_string("3.2.1")
        that2 = Version.from_string("3.2")
        that3 = Version.from_string("3.1.1")
        that4 = Version.from_string("2")
        t.assertFalse(this < that1)
        t.assertFalse(this < that2)
        t.assertFalse(this < that3)
        t.assertFalse(this < that4)

    def test_less_equal_success(t):
        this = Version.from_string("3.2.1")
        that1 = Version.from_string("3.2.1")
        that2 = Version.from_string("3.2.2")
        that3 = Version.from_string("3.3")
        that4 = Version.from_string("4")
        t.assertTrue(this <= that1)
        t.assertTrue(this <= that2)
        t.assertTrue(this <= that3)
        t.assertTrue(this <= that4)

    def test_less_equal_failure(t):
        this = Version.from_string("3.2.1")
        that1 = Version.from_string("3.2")
        that2 = Version.from_string("3.1.1")
        that3 = Version.from_string("2")
        t.assertFalse(this <= that1)
        t.assertFalse(this <= that2)
        t.assertFalse(this <= that3)

    def test_greater_than_success(t):
        this = Version.from_string("3.2.1")
        that1 = Version.from_string("3.2")
        that2 = Version.from_string("3.1.1")
        that3 = Version.from_string("2")
        t.assertTrue(this > that1)
        t.assertTrue(this > that2)
        t.assertTrue(this > that3)

    def test_greater_than_failure(t):
        this = Version.from_string("3.2.1")
        that1 = Version.from_string("3.2.1")
        that2 = Version.from_string("3.2.2")
        that3 = Version.from_string("3.3")
        that4 = Version.from_string("4")
        t.assertFalse(this > that1)
        t.assertFalse(this > that2)
        t.assertFalse(this > that3)
        t.assertFalse(this > that4)

    def test_greater_equal_success(t):
        this = Version.from_string("3.2.1")
        that1 = Version.from_string("3.2.1")
        that2 = Version.from_string("3.2")
        that3 = Version.from_string("3.1.1")
        that4 = Version.from_string("2")
        t.assertTrue(this >= that1)
        t.assertTrue(this >= that2)
        t.assertTrue(this >= that3)
        t.assertTrue(this >= that4)

    def test_greater_equal_failure(t):
        this = Version.from_string("3.2.1")
        that1 = Version.from_string("3.2.2")
        that2 = Version.from_string("3.3")
        that3 = Version.from_string("4")
        t.assertFalse(this >= that1)
        t.assertFalse(this >= that2)
        t.assertFalse(this >= that3)
