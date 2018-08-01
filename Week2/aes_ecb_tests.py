import unittest

from aes import AES


class TestingAES(unittest.TestCase):
    def setUp(self):
        """Currently nothing to do. Use it for initialization data before test"""
        pass

    def tearDown(self):
        """Currently nothing to do. Use it for reinitialization data after test"""
        pass

    def test__AES128_Encrypt_PeriodicA__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaa', encoding='ascii'))
        enc_msg = aes.encrypt(bytes('aaaaaaaaaaaaaaaa', encoding='ascii'))
        self.assertEqual(enc_msg, bytes.fromhex('5188C6474B228CBDD242E9125EBE1D53'))

    def test__AES128_Encrypt_PeriodicAB__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaa', encoding='ascii'))
        enc_msg = aes.encrypt(bytes('abababababababab', encoding='ascii'))
        self.assertEqual(enc_msg, bytes.fromhex('1806E8C195C426CE33A6F53495C75E7C'))

    def test__AES128_Encrypt_PeriodicBC__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaa', encoding='ascii'))
        enc_msg = aes.encrypt(bytes('bcbcbcbcbcbcbcbc', encoding='ascii'))
        self.assertEqual(enc_msg, bytes.fromhex('A15C57E515D484873825D0E08E27B8A0'))

    def test__AES128_Encrypt_PeriodicEnglishAlphabet__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaa', encoding='ascii'))
        enc_msg = aes.encrypt(bytes('abcdefghijklmnop', encoding='ascii'))
        self.assertEqual(enc_msg, bytes.fromhex('B72BE667BFB231E45800E956B97C2FAE'))

    def test__AES128_Decrypt_PeriodicA__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaa', encoding='ascii'))
        dec_msg = aes.decrypt(bytes.fromhex('5188C6474B228CBDD242E9125EBE1D53'))
        self.assertEqual(dec_msg, bytes('aaaaaaaaaaaaaaaa', encoding='ascii'))

    def test__AES128_Decrypt_PeriodicAB__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaa', encoding='ascii'))
        dec_msg = aes.decrypt(bytes.fromhex('1806E8C195C426CE33A6F53495C75E7C'))
        self.assertEqual(dec_msg, bytes('abababababababab', encoding='ascii'))

    def test__AES128_Decrypt_PeriodicBC__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaa', encoding='ascii'))
        dec_msg = aes.decrypt(bytes.fromhex('A15C57E515D484873825D0E08E27B8A0'))
        self.assertEqual(dec_msg, bytes('bcbcbcbcbcbcbcbc', encoding='ascii'))

    def test__AES128_Decrypt_PeriodicEnglishAlphabet__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaa', encoding='ascii'))
        dec_msg = aes.decrypt(bytes.fromhex('B72BE667BFB231E45800E956B97C2FAE'))
        self.assertEqual(dec_msg, bytes('abcdefghijklmnop', encoding='ascii'))

    def test__AES192_Encrypt_PeriodicA__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'))
        enc_msg = aes.encrypt(bytes('aaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'))
        self.assertEqual(enc_msg, bytes.fromhex('B60700284ECBA59FA24962D00CF9C2'))
