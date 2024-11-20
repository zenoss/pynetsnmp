import unittest

from pynetsnmp import usm


class TestUser(unittest.TestCase):
    name = "john_doe"
    passwd = "secured123"  # noqa: S105

    def test_default(t):
        user = usm.User(t.name)
        t.assertEqual(t.name, user.name)
        t.assertEqual(usm.Authentication.new_noauth(), user.auth)
        t.assertEqual(usm.Privacy.new_nopriv(), user.priv)
        t.assertIsNone(user.engine)
        t.assertIsNone(user.context)
        t.assertEqual(user.version, "3")
        expected = ("-v", "3", "-u", t.name, "-l", "noAuthNoPriv")
        t.assertSequenceEqual(expected, user.getArguments())

    def test_engineid(t):
        engineid = hex(3443489794829589283483234)[2:].strip("L")
        user = usm.User(t.name, engine=engineid)
        t.assertEqual(t.name, user.name)
        t.assertEqual(usm.Authentication.new_noauth(), user.auth)
        t.assertEqual(usm.Privacy.new_nopriv(), user.priv)
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
        user = usm.User(t.name, context=contextid)
        t.assertEqual(t.name, user.name)
        t.assertEqual(usm.Authentication.new_noauth(), user.auth)
        t.assertEqual(usm.Privacy.new_nopriv(), user.priv)
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
        auth = usm.Authentication(usm.AUTH_SHA_224, t.passwd)
        user = usm.User(t.name, auth=auth)
        t.assertEqual(t.name, user.name)
        t.assertEqual(auth, user.auth)
        t.assertEqual(usm.Privacy.new_nopriv(), user.priv)
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
        auth = usm.Authentication(usm.AUTH_SHA_224, t.passwd)
        priv = usm.Privacy(usm.PRIV_AES_256, t.passwd)
        user = usm.User(t.name, auth=auth, priv=priv)
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
        auth = usm.Authentication(usm.AUTH_SHA_224, t.passwd)
        priv = usm.Privacy(usm.PRIV_AES_256, t.passwd)
        contextid = hex(9084090984572743455234)[2:].strip("L")
        engineid = hex(3443489794829589283483234)[2:].strip("L")
        user = usm.User(
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
        auth1 = usm.Authentication(usm.AUTH_SHA_224, t.passwd)
        user1 = usm.User(t.name, auth=auth1)
        auth2 = usm.Authentication(usm.AUTH_SHA_224, t.passwd)
        user2 = usm.User(t.name, auth=auth2)
        auth3 = usm.Authentication(usm.AUTH_SHA_256, t.passwd)
        priv3 = usm.Privacy(usm.PRIV_AES_256, t.passwd)
        user3 = usm.User(t.name, auth=auth3, priv=priv3)
        t.assertEqual(user1, user2)
        t.assertNotEqual(user1, user3)
