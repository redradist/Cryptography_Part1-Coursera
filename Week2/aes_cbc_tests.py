import unittest

from aes import AES


class Testing_AES_CBC(unittest.TestCase):
    def setUp(self):
        """Currently nothing to do. Use it for initialization data before test"""
        pass

    def tearDown(self):
        """Currently nothing to do. Use it for reinitialization data after test"""
        pass

    def test__AES128_Encrypt_PeriodicA__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaa', encoding='ascii'),
                  [0x34, 0x99, 0xc6, 0x0e, 0xea, 0x22, 0x74, 0x53, 0xc7, 0x79, 0xde, 0x50, 0xfc, 0x84, 0xe2, 0x17])
        enc_msg = aes.encrypt(bytes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'), mode='CBC')
        self.assertEqual(enc_msg, bytes.fromhex('f0130bd72e27c31bb1b53a209863fa4e47530c2112ec5b1b203a71d3a4a126e8'))

    def test__AES128_Encrypt_PeriodicAB__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaa', encoding='ascii'),
                  [0x34, 0x99, 0xc6, 0x0e, 0xea, 0x22, 0x74, 0x53, 0xc7, 0x79, 0xde, 0x50, 0xfc, 0x84, 0xe2, 0x17])
        enc_msg = aes.encrypt(bytes('abababababababababababababababab', encoding='ascii'), mode='CBC')
        self.assertEqual(enc_msg, bytes.fromhex('c27f75c3a7e4266f1375853000ea8a0ee11d6c3da0b1a6eaf88f1c8bae08ffb6'))

    def test__AES128_Encrypt_PeriodicBC__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaa', encoding='ascii'),
                  [0x34, 0x99, 0xc6, 0x0e, 0xea, 0x22, 0x74, 0x53, 0xc7, 0x79, 0xde, 0x50, 0xfc, 0x84, 0xe2, 0x17])
        enc_msg = aes.encrypt(bytes('bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc', encoding='ascii'), mode='CBC')
        self.assertEqual(enc_msg, bytes.fromhex('0fbe03e305d80bdd081074f287d103825eb0920b8ca3d56e33cdf1fbaf7944ba'))

    def test__AES128_Encrypt_PeriodicEnglishAlphabet__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaa', encoding='ascii'),
                  [0x34, 0x99, 0xc6, 0x0e, 0xea, 0x22, 0x74, 0x53, 0xc7, 0x79, 0xde, 0x50, 0xfc, 0x84, 0xe2, 0x17])
        enc_msg = aes.encrypt(bytes('abcdefghijklmnopabcdefghijklmnop', encoding='ascii'), mode='CBC')
        self.assertEqual(enc_msg, bytes.fromhex('911a7b25e138adfe7507192d7c96aa4a544b6cab9f4fccff141107430f9de955'))

    def test__AES128_Decrypt_PeriodicA__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaa', encoding='ascii'),
                  [0x34, 0x99, 0xc6, 0x0e, 0xea, 0x22, 0x74, 0x53, 0xc7, 0x79, 0xde, 0x50, 0xfc, 0x84, 0xe2, 0x17])
        dec_msg = aes.decrypt(bytes.fromhex('f0130bd72e27c31bb1b53a209863fa4e47530c2112ec5b1b203a71d3a4a126e8'), mode='CBC')
        self.assertEqual(dec_msg, bytes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'))

    def test__AES128_Decrypt_PeriodicAB__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaa', encoding='ascii'),
                  [0x34, 0x99, 0xc6, 0x0e, 0xea, 0x22, 0x74, 0x53, 0xc7, 0x79, 0xde, 0x50, 0xfc, 0x84, 0xe2, 0x17])
        dec_msg = aes.decrypt(bytes.fromhex('c27f75c3a7e4266f1375853000ea8a0ee11d6c3da0b1a6eaf88f1c8bae08ffb6'), mode='CBC')
        self.assertEqual(dec_msg, bytes('abababababababababababababababab', encoding='ascii'))

    def test__AES128_Decrypt_PeriodicBC__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaa', encoding='ascii'),
                  [0x34, 0x99, 0xc6, 0x0e, 0xea, 0x22, 0x74, 0x53, 0xc7, 0x79, 0xde, 0x50, 0xfc, 0x84, 0xe2, 0x17])
        dec_msg = aes.decrypt(bytes.fromhex('0fbe03e305d80bdd081074f287d103825eb0920b8ca3d56e33cdf1fbaf7944ba'), mode='CBC')
        self.assertEqual(dec_msg, bytes('bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc', encoding='ascii'))

    def test__AES128_Decrypt_PeriodicEnglishAlphabet__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaa', encoding='ascii'),
                  [0x34, 0x99, 0xc6, 0x0e, 0xea, 0x22, 0x74, 0x53, 0xc7, 0x79, 0xde, 0x50, 0xfc, 0x84, 0xe2, 0x17])
        dec_msg = aes.decrypt(bytes.fromhex('911a7b25e138adfe7507192d7c96aa4a544b6cab9f4fccff141107430f9de955'), mode='CBC')
        self.assertEqual(dec_msg, bytes('abcdefghijklmnopabcdefghijklmnop', encoding='ascii'))

    def test__AES192_Encrypt_PeriodicA__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'),
                  [0xb1, 0xc7, 0x6a, 0xec, 0x76, 0x74, 0x86, 0x5d, 0x53, 0x46, 0xb3, 0xb0, 0xd1, 0xcb, 0x2c, 0x22])
        enc_msg = aes.encrypt(bytes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'), mode='CBC')
        self.assertEqual(enc_msg, bytes.fromhex('4b30726a54367b5623d172f7656625fb7d7570c68ff6713aa4a67c0c782dcab7'))

    def test__AES192_Encrypt_PeriodicAB__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'),
                  [0xb1, 0xc7, 0x6a, 0xec, 0x76, 0x74, 0x86, 0x5d, 0x53, 0x46, 0xb3, 0xb0, 0xd1, 0xcb, 0x2c, 0x22])
        enc_msg = aes.encrypt(bytes('abababababababababababababababab', encoding='ascii'), mode='CBC')
        self.assertEqual(enc_msg, bytes.fromhex('5eaeab24c89ba1b6be04a2a08073d4d7665812b4eeadea2a983a3d5505d39416'))

    def test__AES192_Encrypt_PeriodicBC__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'),
                  [0xb1, 0xc7, 0x6a, 0xec, 0x76, 0x74, 0x86, 0x5d, 0x53, 0x46, 0xb3, 0xb0, 0xd1, 0xcb, 0x2c, 0x22])
        enc_msg = aes.encrypt(bytes('bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc', encoding='ascii'), mode='CBC')
        self.assertEqual(enc_msg, bytes.fromhex('5c1256fe11bc1fa3e684803eae32ae030b5ba3b574451fc15541d92369d9848c'))

    def test__AAES192_Encrypt_PeriodicEnglishAlphabet__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'),
                  [0xb1, 0xc7, 0x6a, 0xec, 0x76, 0x74, 0x86, 0x5d, 0x53, 0x46, 0xb3, 0xb0, 0xd1, 0xcb, 0x2c, 0x22])
        enc_msg = aes.encrypt(bytes('abcdefghijklmnopabcdefghijklmnop', encoding='ascii'), mode='CBC')
        self.assertEqual(enc_msg, bytes.fromhex('3d3d7d6cdd47263cb591cac9ffe5bd96c0e27c4ceb53a581fc2ad24b18499b51'))

    def test__AES192_Decrypt_PeriodicA__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'),
                  [0xb1, 0xc7, 0x6a, 0xec, 0x76, 0x74, 0x86, 0x5d, 0x53, 0x46, 0xb3, 0xb0, 0xd1, 0xcb, 0x2c, 0x22])
        dec_msg = aes.decrypt(bytes.fromhex('4b30726a54367b5623d172f7656625fb7d7570c68ff6713aa4a67c0c782dcab7'), mode='CBC')
        self.assertEqual(dec_msg, bytes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'))

    def test__AES192_Decrypt_PeriodicAB__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'),
                  [0xb1, 0xc7, 0x6a, 0xec, 0x76, 0x74, 0x86, 0x5d, 0x53, 0x46, 0xb3, 0xb0, 0xd1, 0xcb, 0x2c, 0x22])
        dec_msg = aes.decrypt(bytes.fromhex('5eaeab24c89ba1b6be04a2a08073d4d7665812b4eeadea2a983a3d5505d39416'), mode='CBC')
        self.assertEqual(dec_msg, bytes('abababababababababababababababab', encoding='ascii'))

    def test__AES192_Decrypt_PeriodicBC__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'),
                  [0xb1, 0xc7, 0x6a, 0xec, 0x76, 0x74, 0x86, 0x5d, 0x53, 0x46, 0xb3, 0xb0, 0xd1, 0xcb, 0x2c, 0x22])
        dec_msg = aes.decrypt(bytes.fromhex('5c1256fe11bc1fa3e684803eae32ae030b5ba3b574451fc15541d92369d9848c'), mode='CBC')
        self.assertEqual(dec_msg, bytes('bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc', encoding='ascii'))

    def test__AES192_Decrypt_PeriodicEnglishAlphabet__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'),
                  [0xb1, 0xc7, 0x6a, 0xec, 0x76, 0x74, 0x86, 0x5d, 0x53, 0x46, 0xb3, 0xb0, 0xd1, 0xcb, 0x2c, 0x22])
        dec_msg = aes.decrypt(bytes.fromhex('3d3d7d6cdd47263cb591cac9ffe5bd96c0e27c4ceb53a581fc2ad24b18499b51'), mode='CBC')
        self.assertEqual(dec_msg, bytes('abcdefghijklmnopabcdefghijklmnop', encoding='ascii'))

    def test__AES256_Encrypt_PeriodicA__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'),
                  [0x68, 0xf8, 0x4a, 0x59, 0xa3, 0xca, 0x2d, 0x0e, 0x5c, 0xb1, 0x64, 0x6f, 0xbb, 0x16, 0x4d, 0xa4])
        enc_msg = aes.encrypt(bytes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'), mode='CBC')
        self.assertEqual(enc_msg, bytes.fromhex('f3d5d8a0097fa114f798293cd837dd080b2b675d14d1e8cb52c3b57ff128c2f2'))

    def test__AES256_Encrypt_PeriodicAB__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'),
                  [0x68, 0xf8, 0x4a, 0x59, 0xa3, 0xca, 0x2d, 0x0e, 0x5c, 0xb1, 0x64, 0x6f, 0xbb, 0x16, 0x4d, 0xa4])
        enc_msg = aes.encrypt(bytes('abababababababababababababababab', encoding='ascii'), mode='CBC')
        self.assertEqual(enc_msg, bytes.fromhex('301d248423445c4569d59c40bfe7c0cddc0a2c97024c082826097bb537e4f6fd'))

    def test__AES256_Encrypt_PeriodicBC__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'),
                  [0x68, 0xf8, 0x4a, 0x59, 0xa3, 0xca, 0x2d, 0x0e, 0x5c, 0xb1, 0x64, 0x6f, 0xbb, 0x16, 0x4d, 0xa4])
        enc_msg = aes.encrypt(bytes('bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc', encoding='ascii'), mode='CBC')
        self.assertEqual(enc_msg, bytes.fromhex('e3be46f516d867556907171f3b28be221e3b267b0f575778f148630a5e285e58'))

    def test__AES256_Encrypt_PeriodicEnglishAlphabet__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'),
                  [0x68, 0xf8, 0x4a, 0x59, 0xa3, 0xca, 0x2d, 0x0e, 0x5c, 0xb1, 0x64, 0x6f, 0xbb, 0x16, 0x4d, 0xa4])
        enc_msg = aes.encrypt(bytes('abcdefghijklmnopabcdefghijklmnop', encoding='ascii'), mode='CBC')
        self.assertEqual(enc_msg, bytes.fromhex('452f2f1d6357ae9e64df11f895141305778ccab1e7f7a698f350d13b6460f346'))

    def test__AES256_Decrypt_PeriodicA__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'),
                  [0x68, 0xf8, 0x4a, 0x59, 0xa3, 0xca, 0x2d, 0x0e, 0x5c, 0xb1, 0x64, 0x6f, 0xbb, 0x16, 0x4d, 0xa4])
        dec_msg = aes.decrypt(bytes.fromhex('f3d5d8a0097fa114f798293cd837dd080b2b675d14d1e8cb52c3b57ff128c2f2'), mode='CBC')
        self.assertEqual(dec_msg, bytes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'))

    def test__AES256_Decrypt_PeriodicAB__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'),
                  [0x68, 0xf8, 0x4a, 0x59, 0xa3, 0xca, 0x2d, 0x0e, 0x5c, 0xb1, 0x64, 0x6f, 0xbb, 0x16, 0x4d, 0xa4])
        dec_msg = aes.decrypt(bytes.fromhex('301d248423445c4569d59c40bfe7c0cddc0a2c97024c082826097bb537e4f6fd'), mode='CBC')
        self.assertEqual(dec_msg, bytes('abababababababababababababababab', encoding='ascii'))

    def test__AES256_Decrypt_PeriodicBC__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'),
                  [0x68, 0xf8, 0x4a, 0x59, 0xa3, 0xca, 0x2d, 0x0e, 0x5c, 0xb1, 0x64, 0x6f, 0xbb, 0x16, 0x4d, 0xa4])
        dec_msg = aes.decrypt(bytes.fromhex('e3be46f516d867556907171f3b28be221e3b267b0f575778f148630a5e285e58'), mode='CBC')
        self.assertEqual(dec_msg, bytes('bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc', encoding='ascii'))

    def test__AES256_Decrypt_PeriodicEnglishAlphabet__Valid(self):
        aes = AES(bytes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', encoding='ascii'),
                  [0x68, 0xf8, 0x4a, 0x59, 0xa3, 0xca, 0x2d, 0x0e, 0x5c, 0xb1, 0x64, 0x6f, 0xbb, 0x16, 0x4d, 0xa4])
        dec_msg = aes.decrypt(bytes.fromhex('452f2f1d6357ae9e64df11f895141305778ccab1e7f7a698f350d13b6460f346'), mode='CBC')
        self.assertEqual(dec_msg, bytes('abcdefghijklmnopabcdefghijklmnop', encoding='ascii'))
