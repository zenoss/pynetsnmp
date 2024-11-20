import unittest

from pynetsnmp import usm


class TestPrivacy(unittest.TestCase):
    passwd = "security123"  # noqa: S105

    def test_nopriv_classmethod(t):
        priv = usm.Privacy.new_nopriv()
        t.assertEqual(usm.PRIV_NOPRIV, priv.protocol)
        t.assertIsNone(priv.passphrase)

    def test_none_init(t):
        priv = usm.Privacy(None, None)
        t.assertEqual(usm.PRIV_NOPRIV, priv.protocol)
        t.assertIsNone(priv.passphrase)

        priv = usm.Privacy(None, t.passwd)
        t.assertEqual(usm.PRIV_NOPRIV, priv.protocol)
        t.assertIsNone(priv.passphrase)

    def test_nopriv_init(t):
        priv = usm.Privacy(usm.PRIV_NOPRIV, None)
        t.assertEqual(usm.PRIV_NOPRIV, priv.protocol)
        t.assertIsNone(priv.passphrase)

        priv = usm.Privacy(usm.PRIV_NOPRIV, t.passwd)
        t.assertEqual(usm.PRIV_NOPRIV, priv.protocol)
        t.assertIsNone(priv.passphrase)

    def test_nopriv_str_init(t):
        priv = usm.Privacy("PRIV_NOPRIV", None)
        t.assertEqual(usm.PRIV_NOPRIV, priv.protocol)
        t.assertIsNone(priv.passphrase)

        priv = usm.Privacy("PRIV_NOPRIV", t.passwd)
        t.assertEqual(usm.PRIV_NOPRIV, priv.protocol)
        t.assertIsNone(priv.passphrase)

    def test_nopriv_is_false(t):
        priv = usm.Privacy.new_nopriv()
        t.assertFalse(priv)

    def test_des(t):
        priv = usm.Privacy(usm.PRIV_DES, t.passwd)
        t.assertTrue(priv)
        t.assertEqual(priv.protocol, usm.PRIV_DES)
        t.assertEqual(priv.passphrase, t.passwd)

    def test_aes(t):
        priv = usm.Privacy(usm.PRIV_AES, t.passwd)
        t.assertTrue(priv)
        t.assertEqual(priv.protocol, usm.PRIV_AES)
        t.assertEqual(priv.passphrase, t.passwd)

    def test_aes_192(t):
        priv = usm.Privacy(usm.PRIV_AES_192, t.passwd)
        t.assertTrue(priv)
        t.assertEqual(priv.protocol, usm.PRIV_AES_192)
        t.assertEqual(priv.passphrase, t.passwd)

    def test_aes_256(t):
        priv = usm.Privacy(usm.PRIV_AES_256, t.passwd)
        t.assertTrue(priv)
        t.assertEqual(priv.protocol, usm.PRIV_AES_256)
        t.assertEqual(priv.passphrase, t.passwd)

    def test_equal(t):
        priv1 = usm.Privacy(usm.PRIV_DES, t.passwd)
        priv2 = usm.Privacy(usm.PRIV_DES, t.passwd)
        t.assertEqual(priv1, priv2)

    def test_not_equal(t):
        priv1 = usm.Privacy(usm.PRIV_DES, t.passwd)
        priv2 = usm.Privacy(usm.PRIV_AES, t.passwd)
        t.assertNotEqual(priv1, priv2)

        priv3 = usm.Privacy(usm.PRIV_AES, t.passwd + "456")
        t.assertNotEqual(priv2, priv3)
