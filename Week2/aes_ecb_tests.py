import unittest

from aes import AES


class Testing_AES_ECB(unittest.TestCase):
    def setUp(self):
        """Currently nothing to do. Use it for initialization data before test"""
        pass

    def tearDown(self):
        """Currently nothing to do. Use it for reinitialization data after test"""
        pass

    def test__AES128_Encrypt_PeriodicA__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaa', encoding='ascii'))
        enc_msg = aes.encrypt(bytes('aaaaaaaaaaaaaaaa', encoding='ascii'))
        self.assertEqual(enc_msg, bytes.fromhex('5188c6474b228cbdd242e9125ebe1d53'))

    def test__AES128_Encrypt_PeriodicAB__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaa', encoding='ascii'))
        enc_msg = aes.encrypt(bytes('abababababababab', encoding='ascii'))
        self.assertEqual(enc_msg, bytes.fromhex('1806e8c195c426ce33a6f53495c75e7c'))

    def test__AES128_Encrypt_PeriodicBC__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaa', encoding='ascii'))
        enc_msg = aes.encrypt(bytes('bcbcbcbcbcbcbcbc', encoding='ascii'))
        self.assertEqual(enc_msg, bytes.fromhex('a15c57e515d484873825d0e08e27b8a0'))

    def test__AES128_Encrypt_PeriodicEnglishAlphabet__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaa', encoding='ascii'))
        enc_msg = aes.encrypt(bytes('abcdefghijklmnop', encoding='ascii'))
        self.assertEqual(enc_msg, bytes.fromhex('b72be667bfb231e45800e956b97c2fae'))

    def test__AES128_Decrypt_PeriodicA__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaa', encoding='ascii'))
        dec_msg = aes.decrypt(bytes.fromhex('5188c6474b228cbdd242e9125ebe1d53'))
        self.assertEqual(dec_msg, bytes('aaaaaaaaaaaaaaaa', encoding='ascii'))

    def test__AES128_Decrypt_PeriodicAB__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaa', encoding='ascii'))
        dec_msg = aes.decrypt(bytes.fromhex('1806e8c195c426ce33a6f53495c75e7c'))
        self.assertEqual(dec_msg, bytes('abababababababab', encoding='ascii'))

    def test__AES128_Decrypt_PeriodicBC__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaa', encoding='ascii'))
        dec_msg = aes.decrypt(bytes.fromhex('a15c57e515d484873825d0e08e27b8a0'))
        self.assertEqual(dec_msg, bytes('bcbcbcbcbcbcbcbc', encoding='ascii'))

    def test__AES128_Decrypt_PeriodicEnglishAlphabet__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaa', encoding='ascii'))
        dec_msg = aes.decrypt(bytes.fromhex('b72be667bfb231e45800e956b97c2fae'))
        self.assertEqual(dec_msg, bytes('abcdefghijklmnop', encoding='ascii'))

    def test__AES192_Encrypt_PeriodicA__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'))
        enc_msg = aes.encrypt(bytes('aaaaaaaaaaaaaaaa', encoding='ascii'))
        self.assertEqual(enc_msg, bytes.fromhex('b60700284ecba59fa24962d00cf9c299'))

    def test__AES192_Encrypt_PeriodicAB__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'))
        enc_msg = aes.encrypt(bytes('abababababababab', encoding='ascii'))
        self.assertEqual(enc_msg, bytes.fromhex('690e0ecc29930889a0d47a944f17b658'))

    def test__AES192_Encrypt_PeriodicBC__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'))
        enc_msg = aes.encrypt(bytes('bcbcbcbcbcbcbcbc', encoding='ascii'))
        self.assertEqual(enc_msg, bytes.fromhex('3a3d2cca3e7e7a2eb07826e2498f711c'))

    def test__AES192_Encrypt_PeriodicEnglishAlphabet__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'))
        enc_msg = aes.encrypt(bytes('abcdefghijklmnop', encoding='ascii'))
        self.assertEqual(enc_msg, bytes.fromhex('cb03edd12fb7ea19c8a4a95d6fb6df8e'))

    def test__AES192_Decrypt_PeriodicA__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'))
        dec_msg = aes.decrypt(bytes.fromhex('b60700284ecba59fa24962d00cf9c299'))
        self.assertEqual(dec_msg, bytes('aaaaaaaaaaaaaaaa', encoding='ascii'))

    def test__AES192_Decrypt_PeriodicAB__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'))
        dec_msg = aes.decrypt(bytes.fromhex('690e0ecc29930889a0d47a944f17b658'))
        self.assertEqual(dec_msg, bytes('abababababababab', encoding='ascii'))

    def test__AES192_Decrypt_PeriodicBC__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'))
        dec_msg = aes.decrypt(bytes.fromhex('3a3d2cca3e7e7a2eb07826e2498f711c'))
        self.assertEqual(dec_msg, bytes('bcbcbcbcbcbcbcbc', encoding='ascii'))

    def test__AES192_Decrypt_PeriodicEnglishAlphabet__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'))
        dec_msg = aes.decrypt(bytes.fromhex('cb03edd12fb7ea19c8a4a95d6fb6df8e'))
        self.assertEqual(dec_msg, bytes('abcdefghijklmnop', encoding='ascii'))

    def test__AES256_Encrypt_PeriodicA__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'))
        enc_msg = aes.encrypt(bytes('aaaaaaaaaaaaaaaa', encoding='ascii'))
        self.assertEqual(enc_msg, bytes.fromhex('2ccd45896fc3525e03c7cb97b66895ff'))

    def test__AES256_Encrypt_PeriodicAB__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'))
        enc_msg = aes.encrypt(bytes('abababababababab', encoding='ascii'))
        self.assertEqual(enc_msg, bytes.fromhex('19fa9a9ce608af93221470a62707d29d'))

    def test__AES256_Encrypt_PeriodicBC__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'))
        enc_msg = aes.encrypt(bytes('bcbcbcbcbcbcbcbc', encoding='ascii'))
        self.assertEqual(enc_msg, bytes.fromhex('2499f49e95c204b4ca782ed4c8c592ca'))

    def test__AES256_Encrypt_PeriodicEnglishAlphabet__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'))
        enc_msg = aes.encrypt(bytes('abcdefghijklmnop', encoding='ascii'))
        self.assertEqual(enc_msg, bytes.fromhex('ab168814674b512b604c739a63059e86'))

    def test__AES256_Decrypt_PeriodicA__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'))
        dec_msg = aes.decrypt(bytes.fromhex('2ccd45896fc3525e03c7cb97b66895ff'))
        self.assertEqual(dec_msg, bytes('aaaaaaaaaaaaaaaa', encoding='ascii'))

    def test__AES256_Decrypt_PeriodicAB__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'))
        dec_msg = aes.decrypt(bytes.fromhex('19fa9a9ce608af93221470a62707d29d'))
        self.assertEqual(dec_msg, bytes('abababababababab', encoding='ascii'))

    def test__AES256_Decrypt_PeriodicBC__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'))
        dec_msg = aes.decrypt(bytes.fromhex('2499f49e95c204b4ca782ed4c8c592ca'))
        self.assertEqual(dec_msg, bytes('bcbcbcbcbcbcbcbc', encoding='ascii'))

    def test__AES256_Decrypt_PeriodicEnglishAlphabet__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'))
        dec_msg = aes.decrypt(bytes.fromhex('ab168814674b512b604c739a63059e86'))
        self.assertEqual(dec_msg, bytes('abcdefghijklmnop', encoding='ascii'))
