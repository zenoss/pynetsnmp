import unittest

from pynetsnmp import CONSTANTS, usm


class TestCommunity(unittest.TestCase):
    name = "public"

    def test_default(t):
        c = usm.Community(t.name)
        t.assertEqual(c.name, t.name)
        t.assertEqual(c.version, "2c")
        expected = ("-v", "2c", "-c", t.name)
        t.assertSequenceEqual(c.getArguments(), expected)

    def test_v1_constant(t):
        c = usm.Community(t.name, CONSTANTS.SNMP_VERSION_1)
        t.assertEqual(c.name, t.name)
        t.assertEqual(c.version, "1")
        expected = ("-v", "1", "-c", t.name)
        t.assertSequenceEqual(c.getArguments(), expected)

    def test_v1_v1(t):
        c = usm.Community(t.name, "v1")
        t.assertEqual(c.name, t.name)
        t.assertEqual(c.version, "1")
        expected = ("-v", "1", "-c", t.name)
        t.assertSequenceEqual(c.getArguments(), expected)

    def test_v2c_constant(t):
        c = usm.Community(t.name, CONSTANTS.SNMP_VERSION_2c)
        t.assertEqual(c.name, t.name)
        t.assertEqual(c.version, "2c")
        expected = ("-v", "2c", "-c", t.name)
        t.assertSequenceEqual(c.getArguments(), expected)

    def test_v2c_v2c(t):
        c = usm.Community(t.name, "v2c")
        t.assertEqual(c.name, t.name)
        t.assertEqual(c.version, "2c")
        expected = ("-v", "2c", "-c", t.name)
        t.assertSequenceEqual(c.getArguments(), expected)

    def test_v3_constant(t):
        with t.assertRaises(ValueError):
            usm.Community(t.name, CONSTANTS.SNMP_VERSION_3)

    def test_v3_v3(t):
        with t.assertRaises(ValueError):
            usm.Community(t.name, "v3")

    def test_none_version(t):
        with t.assertRaises(ValueError):
            usm.Community(t.name, None)

    def test_not_a_version_str(t):
        with t.assertRaises(ValueError):
            usm.Community(t.name, "oi")

    def test_not_a_version_number(t):
        with t.assertRaises(ValueError):
            usm.Community(t.name, 3947)
