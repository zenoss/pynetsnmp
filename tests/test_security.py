import unittest

from pynetsnmp import security, usm


class TestCommunity(unittest.TestCase):
    name = "public"

    def test_default(t):
        c = security.Community(t.name)
        t.assertEqual(c.name, t.name)
        t.assertEqual(c.version, "2c")
        expected = ("-v", "2c", "-c", t.name)
        t.assertSequenceEqual(c.getArguments(), expected)

    def test_v1_constant(t):
        c = security.Community(t.name, security.SNMP_VERSION_1)
        t.assertEqual(c.name, t.name)
        t.assertEqual(c.version, "1")
        expected = ("-v", "1", "-c", t.name)
        t.assertSequenceEqual(c.getArguments(), expected)

    def test_v1_v1(t):
        c = security.Community(t.name, "v1")
        t.assertEqual(c.name, t.name)
        t.assertEqual(c.version, "1")
        expected = ("-v", "1", "-c", t.name)
        t.assertSequenceEqual(c.getArguments(), expected)

    def test_v2c_constant(t):
        c = security.Community(t.name, security.SNMP_VERSION_2c)
        t.assertEqual(c.name, t.name)
        t.assertEqual(c.version, "2c")
        expected = ("-v", "2c", "-c", t.name)
        t.assertSequenceEqual(c.getArguments(), expected)

    def test_v2c_v2c(t):
        c = security.Community(t.name, "v2c")
        t.assertEqual(c.name, t.name)
        t.assertEqual(c.version, "2c")
        expected = ("-v", "2c", "-c", t.name)
        t.assertSequenceEqual(c.getArguments(), expected)

    def test_v3_constant(t):
        with t.assertRaises(ValueError):
            security.Community(t.name, security.SNMP_VERSION_3)

    def test_v3_v3(t):
        with t.assertRaises(ValueError):
            security.Community(t.name, "v3")

    def test_none_version(t):
        with t.assertRaises(ValueError):
            security.Community(t.name, None)

    def test_not_a_version_str(t):
        with t.assertRaises(ValueError):
            security.Community(t.name, "oi")

    def test_not_a_version_number(t):
        with t.assertRaises(ValueError):
            security.Community(t.name, 3947)


class TestUsmUser(unittest.TestCase):
    name = "john_doe"
    passwd = "secured123"  # noqa: S105

    def test_default(t):
        user = security.UsmUser(t.name)
        t.assertEqual(t.name, user.name)
        t.assertEqual(security.Authentication.new_noauth(), user.auth)
        t.assertEqual(security.Privacy.new_nopriv(), user.priv)
        t.assertIsNone(user.engine)
        t.assertIsNone(user.context)
        t.assertEqual(user.version, "3")
        expected = ("-v", "3", "-u", t.name, "-l", "noAuthNoPriv")
        t.assertSequenceEqual(expected, user.getArguments())

    def test_engineid(t):
        engineid = hex(3443489794829589283483234)[2:].strip("L")
        user = security.UsmUser(t.name, engine=engineid)
        t.assertEqual(t.name, user.name)
        t.assertEqual(security.Authentication.new_noauth(), user.auth)
        t.assertEqual(security.Privacy.new_nopriv(), user.priv)
        t.assertEqual(engineid, user.engine)
        t.assertIsNone(user.context)
        expected = (
            "-v",
            "3",
            "-u",
            t.name,
            "-l",
            "noAuthNoPriv",
            "-e",
            engineid,
        )
        t.assertSequenceEqual(expected, user.getArguments())

    def test_contextid(t):
        contextid = hex(9084090984572743455234)[2:].strip("L")
        user = security.UsmUser(t.name, context=contextid)
        t.assertEqual(t.name, user.name)
        t.assertEqual(security.Authentication.new_noauth(), user.auth)
        t.assertEqual(security.Privacy.new_nopriv(), user.priv)
        t.assertIsNone(user.engine)
        t.assertEqual(contextid, user.context)
        expected = (
            "-v",
            "3",
            "-u",
            t.name,
            "-l",
            "noAuthNoPriv",
            "-n",
            contextid,
        )
        t.assertSequenceEqual(expected, user.getArguments())

    def test_auth(t):
        auth = security.Authentication(usm.AUTH_SHA_224, t.passwd)
        user = security.UsmUser(t.name, auth=auth)
        t.assertEqual(t.name, user.name)
        t.assertEqual(auth, user.auth)
        t.assertEqual(security.Privacy.new_nopriv(), user.priv)
        t.assertIsNone(user.engine)
        t.assertIsNone(user.context)
        t.assertEqual(user.version, "3")
        expected = (
            "-v",
            "3",
            "-u",
            t.name,
            "-l",
            "authNoPriv",
            "-a",
            auth.protocol.name,
            "-A",
            auth.passphrase,
        )
        t.assertSequenceEqual(expected, user.getArguments())

    def test_authpriv(t):
        auth = security.Authentication(usm.AUTH_SHA_224, t.passwd)
        priv = security.Privacy(usm.PRIV_AES_256, t.passwd)
        user = security.UsmUser(t.name, auth=auth, priv=priv)
        t.assertEqual(t.name, user.name)
        t.assertEqual(auth, user.auth)
        t.assertEqual(priv, user.priv)
        t.assertIsNone(user.engine)
        t.assertIsNone(user.context)
        t.assertEqual(user.version, "3")
        expected = (
            "-v",
            "3",
            "-u",
            t.name,
            "-l",
            "authPriv",
            "-a",
            auth.protocol.name,
            "-A",
            auth.passphrase,
            "-x",
            priv.protocol.name,
            "-X",
            priv.passphrase,
        )
        t.assertSequenceEqual(expected, user.getArguments())

    def test_all_args(t):
        auth = security.Authentication(usm.AUTH_SHA_224, t.passwd)
        priv = security.Privacy(usm.PRIV_AES_256, t.passwd)
        contextid = hex(9084090984572743455234)[2:].strip("L")
        engineid = hex(3443489794829589283483234)[2:].strip("L")
        user = security.UsmUser(
            t.name, auth=auth, priv=priv, engine=engineid, context=contextid
        )
        t.assertEqual(t.name, user.name)
        t.assertEqual(auth, user.auth)
        t.assertEqual(priv, user.priv)
        t.assertEqual(engineid, user.engine)
        t.assertEqual(contextid, user.context)
        t.assertEqual(user.version, "3")
        expected = (
            "-v",
            "3",
            "-u",
            t.name,
            "-l",
            "authPriv",
            "-a",
            auth.protocol.name,
            "-A",
            auth.passphrase,
            "-x",
            priv.protocol.name,
            "-X",
            priv.passphrase,
            "-e",
            engineid,
            "-n",
            contextid,
        )
        t.assertSequenceEqual(expected, user.getArguments())

    def test_equality(t):
        auth1 = security.Authentication(usm.AUTH_SHA_224, t.passwd)
        user1 = security.UsmUser(t.name, auth=auth1)
        auth2 = security.Authentication(usm.AUTH_SHA_224, t.passwd)
        user2 = security.UsmUser(t.name, auth=auth2)
        auth3 = security.Authentication(usm.AUTH_SHA_256, t.passwd)
        priv3 = security.Privacy(usm.PRIV_AES_256, t.passwd)
        user3 = security.UsmUser(t.name, auth=auth3, priv=priv3)
        t.assertEqual(user1, user2)
        t.assertNotEqual(user1, user3)


class TestAuthentication(unittest.TestCase):
    passwd = "security123"  # noqa: S105

    def test_noauth_classmethod(t):
        auth = security.Authentication.new_noauth()
        t.assertEqual(usm.AUTH_NOAUTH, auth.protocol)
        t.assertIsNone(auth.passphrase)

    def test_none_init(t):
        auth = security.Authentication(None, None)
        t.assertEqual(usm.AUTH_NOAUTH, auth.protocol)
        t.assertIsNone(auth.passphrase)

        auth = security.Authentication(None, t.passwd)
        t.assertEqual(usm.AUTH_NOAUTH, auth.protocol)
        t.assertIsNone(auth.passphrase)

    def test_noauth_init(t):
        auth = security.Authentication(usm.AUTH_NOAUTH, None)
        t.assertEqual(usm.AUTH_NOAUTH, auth.protocol)
        t.assertIsNone(auth.passphrase)

        auth = security.Authentication(usm.AUTH_NOAUTH, t.passwd)
        t.assertEqual(usm.AUTH_NOAUTH, auth.protocol)
        t.assertIsNone(auth.passphrase)

    def test_noauth_str_init(t):
        auth = security.Authentication("AUTH_NOAUTH", None)
        t.assertEqual(usm.AUTH_NOAUTH, auth.protocol)
        t.assertIsNone(auth.passphrase)

        auth = security.Authentication("AUTH_NOAUTH", t.passwd)
        t.assertEqual(usm.AUTH_NOAUTH, auth.protocol)
        t.assertIsNone(auth.passphrase)

    def test_noauth_is_false(t):
        auth = security.Authentication.new_noauth()
        t.assertFalse(auth)

    def test_md5(t):
        auth = security.Authentication(usm.AUTH_MD5, t.passwd)
        t.assertTrue(auth)
        t.assertEqual(auth.protocol, usm.AUTH_MD5)
        t.assertEqual(auth.passphrase, t.passwd)

    def test_sha(t):
        auth = security.Authentication(usm.AUTH_SHA, t.passwd)
        t.assertTrue(auth)
        t.assertEqual(auth.protocol, usm.AUTH_SHA)
        t.assertEqual(auth.passphrase, t.passwd)

    def test_sha_224(t):
        auth = security.Authentication(usm.AUTH_SHA_224, t.passwd)
        t.assertTrue(auth)
        t.assertEqual(auth.protocol, usm.AUTH_SHA_224)
        t.assertEqual(auth.passphrase, t.passwd)

    def test_sha_256(t):
        auth = security.Authentication(usm.AUTH_SHA_256, t.passwd)
        t.assertTrue(auth)
        t.assertEqual(auth.protocol, usm.AUTH_SHA_256)
        t.assertEqual(auth.passphrase, t.passwd)

    def test_sha_384(t):
        auth = security.Authentication(usm.AUTH_SHA_384, t.passwd)
        t.assertTrue(auth)
        t.assertEqual(auth.protocol, usm.AUTH_SHA_384)
        t.assertEqual(auth.passphrase, t.passwd)

    def test_sha_512(t):
        auth = security.Authentication(usm.AUTH_SHA_512, t.passwd)
        t.assertTrue(auth)
        t.assertEqual(auth.protocol, usm.AUTH_SHA_512)
        t.assertEqual(auth.passphrase, t.passwd)

    def test_equal(t):
        auth1 = security.Authentication(usm.AUTH_MD5, t.passwd)
        auth2 = security.Authentication(usm.AUTH_MD5, t.passwd)
        t.assertEqual(auth1, auth2)

    def test_not_equal(t):
        auth1 = security.Authentication(usm.AUTH_MD5, t.passwd)
        auth2 = security.Authentication(usm.AUTH_SHA, t.passwd)
        t.assertNotEqual(auth1, auth2)

        auth3 = security.Authentication(usm.AUTH_SHA, t.passwd + "456")
        t.assertNotEqual(auth2, auth3)


class TestPrivacy(unittest.TestCase):
    passwd = "security123"  # noqa: S105

    def test_nopriv_classmethod(t):
        priv = security.Privacy.new_nopriv()
        t.assertEqual(usm.PRIV_NOPRIV, priv.protocol)
        t.assertIsNone(priv.passphrase)

    def test_none_init(t):
        priv = security.Privacy(None, None)
        t.assertEqual(usm.PRIV_NOPRIV, priv.protocol)
        t.assertIsNone(priv.passphrase)

        priv = security.Privacy(None, t.passwd)
        t.assertEqual(usm.PRIV_NOPRIV, priv.protocol)
        t.assertIsNone(priv.passphrase)

    def test_nopriv_init(t):
        priv = security.Privacy(usm.PRIV_NOPRIV, None)
        t.assertEqual(usm.PRIV_NOPRIV, priv.protocol)
        t.assertIsNone(priv.passphrase)

        priv = security.Privacy(usm.PRIV_NOPRIV, t.passwd)
        t.assertEqual(usm.PRIV_NOPRIV, priv.protocol)
        t.assertIsNone(priv.passphrase)

    def test_nopriv_str_init(t):
        priv = security.Privacy("PRIV_NOPRIV", None)
        t.assertEqual(usm.PRIV_NOPRIV, priv.protocol)
        t.assertIsNone(priv.passphrase)

        priv = security.Privacy("PRIV_NOPRIV", t.passwd)
        t.assertEqual(usm.PRIV_NOPRIV, priv.protocol)
        t.assertIsNone(priv.passphrase)

    def test_nopriv_is_false(t):
        priv = security.Privacy.new_nopriv()
        t.assertFalse(priv)

    def test_des(t):
        priv = security.Privacy(usm.PRIV_DES, t.passwd)
        t.assertTrue(priv)
        t.assertEqual(priv.protocol, usm.PRIV_DES)
        t.assertEqual(priv.passphrase, t.passwd)

    def test_aes(t):
        priv = security.Privacy(usm.PRIV_AES, t.passwd)
        t.assertTrue(priv)
        t.assertEqual(priv.protocol, usm.PRIV_AES)
        t.assertEqual(priv.passphrase, t.passwd)

    def test_aes_192(t):
        priv = security.Privacy(usm.PRIV_AES_192, t.passwd)
        t.assertTrue(priv)
        t.assertEqual(priv.protocol, usm.PRIV_AES_192)
        t.assertEqual(priv.passphrase, t.passwd)

    def test_aes_256(t):
        priv = security.Privacy(usm.PRIV_AES_256, t.passwd)
        t.assertTrue(priv)
        t.assertEqual(priv.protocol, usm.PRIV_AES_256)
        t.assertEqual(priv.passphrase, t.passwd)

    def test_equal(t):
        priv1 = security.Privacy(usm.PRIV_DES, t.passwd)
        priv2 = security.Privacy(usm.PRIV_DES, t.passwd)
        t.assertEqual(priv1, priv2)

    def test_not_equal(t):
        priv1 = security.Privacy(usm.PRIV_DES, t.passwd)
        priv2 = security.Privacy(usm.PRIV_AES, t.passwd)
        t.assertNotEqual(priv1, priv2)

        priv3 = security.Privacy(usm.PRIV_AES, t.passwd + "456")
        t.assertNotEqual(priv2, priv3)
