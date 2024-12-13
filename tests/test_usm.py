import unittest

from pynetsnmp import usm

_sorted_auth_names = sorted(
    ["NOAUTH", "MD5", "SHA", "SHA-224", "SHA-256", "SHA-384", "SHA-512"]
)


class TestAuthProtocols(unittest.TestCase):
    def test_noauth_contained(t):
        t.assertIn(usm.AUTH_NOAUTH, usm.auth_protocols)

    def test_md5_contained(t):
        t.assertIn(usm.AUTH_MD5, usm.auth_protocols)

    def test_sha_contained(t):
        t.assertIn(usm.AUTH_SHA, usm.auth_protocols)

    def test_sha_224_contained(t):
        t.assertIn(usm.AUTH_SHA_224, usm.auth_protocols)

    def test_sha_256_contained(t):
        t.assertIn(usm.AUTH_SHA_256, usm.auth_protocols)

    def test_sha_384_contained(t):
        t.assertIn(usm.AUTH_SHA_384, usm.auth_protocols)

    def test_sha_512_contained(t):
        t.assertIn(usm.AUTH_SHA_512, usm.auth_protocols)

    def test_length(t):
        t.assertEqual(7, len(usm.auth_protocols))

    def test_iterable(t):
        names = sorted(str(p) for p in usm.auth_protocols)
        t.assertEqual(7, len(names))
        t.assertListEqual(_sorted_auth_names, names)

    def test_noauth_getitem(t):
        proto = usm.auth_protocols[usm.AUTH_NOAUTH.name]
        t.assertEqual(usm.AUTH_NOAUTH, proto)

    def test_md5_getitem(t):
        proto = usm.auth_protocols[usm.AUTH_MD5.name]
        t.assertEqual(usm.AUTH_MD5, proto)

    def test_sha_getitem(t):
        proto = usm.auth_protocols[usm.AUTH_SHA.name]
        t.assertEqual(usm.AUTH_SHA, proto)

    def test_sha_224_getitem(t):
        proto = usm.auth_protocols[usm.AUTH_SHA_224.name]
        t.assertEqual(usm.AUTH_SHA_224, proto)

    def test_sha_256_getitem(t):
        proto = usm.auth_protocols[usm.AUTH_SHA_256.name]
        t.assertEqual(usm.AUTH_SHA_256, proto)

    def test_sha_384_getitem(t):
        proto = usm.auth_protocols[usm.AUTH_SHA_384.name]
        t.assertEqual(usm.AUTH_SHA_384, proto)

    def test_sha_512_getitem(t):
        proto = usm.auth_protocols[usm.AUTH_SHA_512.name]
        t.assertEqual(usm.AUTH_SHA_512, proto)


_sorted_priv_names = sorted(["NOPRIV", "DES", "AES", "AES-192", "AES-256"])


class TestPrivProtocols(unittest.TestCase):
    def test_nopriv_contained(t):
        t.assertIn(usm.PRIV_NOPRIV, usm.priv_protocols)

    def test_des_contained(t):
        t.assertIn(usm.PRIV_DES, usm.priv_protocols)

    def test_aes_contained(t):
        t.assertIn(usm.PRIV_AES, usm.priv_protocols)

    def test_aes_192_contained(t):
        t.assertIn(usm.PRIV_AES_192, usm.priv_protocols)

    def test_aes_256_contained(t):
        t.assertIn(usm.PRIV_AES_256, usm.priv_protocols)

    def test_length(t):
        t.assertEqual(5, len(usm.priv_protocols))

    def test_iterable(t):
        names = sorted(str(p) for p in usm.priv_protocols)
        t.assertEqual(5, len(names))
        t.assertListEqual(_sorted_priv_names, names)

    def test_nopriv_getitem(t):
        proto = usm.priv_protocols[usm.PRIV_NOPRIV.name]
        t.assertEqual(usm.PRIV_NOPRIV, proto)

    def test_des_getitem(t):
        proto = usm.priv_protocols[usm.PRIV_DES.name]
        t.assertEqual(usm.PRIV_DES, proto)

    def test_aes_getitem(t):
        proto = usm.priv_protocols[usm.PRIV_AES.name]
        t.assertEqual(usm.PRIV_AES, proto)

    def test_aes_192_getitem(t):
        proto = usm.priv_protocols[usm.PRIV_AES_192.name]
        t.assertEqual(usm.PRIV_AES_192, proto)

    def test_aes_256_getitem(t):
        proto = usm.priv_protocols[usm.PRIV_AES_256.name]
        t.assertEqual(usm.PRIV_AES_256, proto)
