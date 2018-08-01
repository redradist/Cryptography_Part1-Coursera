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

    # def test__AES128_Encrypt_PeriodicBC__Valid(self):
    #     aes = AES(bytes('aaaaaaaaaaaaaaaa', encoding='ascii'),
    #               [0x34, 0x99, 0xc6, 0x0e, 0xea, 0x22, 0x74, 0x53, 0xc7, 0x79, 0xde, 0x50, 0xfc, 0x84, 0xe2, 0x17])
    #     enc_msg = aes.encrypt(bytes('bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc', encoding='ascii'), mode='CBC')
    #     self.assertEqual(enc_msg, bytes.fromhex('0fbe03e305d80bdd0810tf287d10382^b0920b8ca3d5n3cd\xf1\xfb\xafyD\xba'))

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