import unittest

from pynetsnmp import usm


class TestAuthentication(unittest.TestCase):
    passwd = "security123"  # noqa: S105

    def test_noauth_classmethod(t):
        auth = usm.Authentication.new_noauth()
        t.assertEqual(usm.AUTH_NOAUTH, auth.protocol)
        t.assertIsNone(auth.passphrase)

    def test_none_init(t):
        auth = usm.Authentication(None, None)
        t.assertEqual(usm.AUTH_NOAUTH, auth.protocol)
        t.assertIsNone(auth.passphrase)

        auth = usm.Authentication(None, t.passwd)
        t.assertEqual(usm.AUTH_NOAUTH, auth.protocol)
        t.assertIsNone(auth.passphrase)

    def test_noauth_init(t):
        auth = usm.Authentication(usm.AUTH_NOAUTH, None)
        t.assertEqual(usm.AUTH_NOAUTH, auth.protocol)
        t.assertIsNone(auth.passphrase)

        auth = usm.Authentication(usm.AUTH_NOAUTH, t.passwd)
        t.assertEqual(usm.AUTH_NOAUTH, auth.protocol)
        t.assertIsNone(auth.passphrase)

    def test_noauth_str_init(t):
        auth = usm.Authentication("AUTH_NOAUTH", None)
        t.assertEqual(usm.AUTH_NOAUTH, auth.protocol)
        t.assertIsNone(auth.passphrase)

        auth = usm.Authentication("AUTH_NOAUTH", t.passwd)
        t.assertEqual(usm.AUTH_NOAUTH, auth.protocol)
        t.assertIsNone(auth.passphrase)

    def test_noauth_is_false(t):
        auth = usm.Authentication.new_noauth()
        t.assertFalse(auth)

    def test_md5(t):
        auth = usm.Authentication(usm.AUTH_MD5, t.passwd)
        t.assertTrue(auth)
        t.assertEqual(auth.protocol, usm.AUTH_MD5)
        t.assertEqual(auth.passphrase, t.passwd)

    def test_sha(t):
        auth = usm.Authentication(usm.AUTH_SHA, t.passwd)
        t.assertTrue(auth)
        t.assertEqual(auth.protocol, usm.AUTH_SHA)
        t.assertEqual(auth.passphrase, t.passwd)

    def test_sha_224(t):
        auth = usm.Authentication(usm.AUTH_SHA_224, t.passwd)
        t.assertTrue(auth)
        t.assertEqual(auth.protocol, usm.AUTH_SHA_224)
        t.assertEqual(auth.passphrase, t.passwd)

    def test_sha_256(t):
        auth = usm.Authentication(usm.AUTH_SHA_256, t.passwd)
        t.assertTrue(auth)
        t.assertEqual(auth.protocol, usm.AUTH_SHA_256)
        t.assertEqual(auth.passphrase, t.passwd)

    def test_sha_384(t):
        auth = usm.Authentication(usm.AUTH_SHA_384, t.passwd)
        t.assertTrue(auth)
        t.assertEqual(auth.protocol, usm.AUTH_SHA_384)
        t.assertEqual(auth.passphrase, t.passwd)

    def test_sha_512(t):
        auth = usm.Authentication(usm.AUTH_SHA_512, t.passwd)
        t.assertTrue(auth)
        t.assertEqual(auth.protocol, usm.AUTH_SHA_512)
        t.assertEqual(auth.passphrase, t.passwd)

    def test_equal(t):
        auth1 = usm.Authentication(usm.AUTH_MD5, t.passwd)
        auth2 = usm.Authentication(usm.AUTH_MD5, t.passwd)
        t.assertEqual(auth1, auth2)

    def test_not_equal(t):
        auth1 = usm.Authentication(usm.AUTH_MD5, t.passwd)
        auth2 = usm.Authentication(usm.AUTH_SHA, t.passwd)
        t.assertNotEqual(auth1, auth2)

        auth3 = usm.Authentication(usm.AUTH_SHA, t.passwd + "456")
        t.assertNotEqual(auth2, auth3)
