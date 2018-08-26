#!/usr/bin/python3

from pycodec.crypto.cipher.aes import AES


def main():
    '''
    Cryptography, Part 1 (Coursera)
    Week2: Examples
    '''
    aes = AES(bytes.fromhex('140b41b22a29beb4061bda66b6747e14'),
              [0x4c, 0xa0, 0x0f, 0xf4, 0xc8, 0x98, 0xd6, 0x1e, 0x1e, 0xdb, 0xf1, 0x80, 0x06, 0x18, 0xfb, 0x28])
    dec_msg = aes.decrypt(bytes.fromhex('28a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81'), mode='CBC')
    print(f'example_msg_0 is {dec_msg}')

    aes = AES(bytes.fromhex('140b41b22a29beb4061bda66b6747e14'),
              [0x5b, 0x68, 0x62, 0x9f, 0xeb, 0x86, 0x06, 0xf9, 0xa6, 0x66, 0x76, 0x70, 0xb7, 0x5b, 0x38, 0xa5])
    dec_msg = aes.decrypt(bytes.fromhex('b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253'), mode='CBC')
    print(f'example_msg_1 is {dec_msg}')

    aes = AES(bytes.fromhex('36f18357be4dbd77f050515c73fcf9f2'),
              [0x69, 0xdd, 0xa8, 0x45, 0x5c, 0x7d, 0xd4, 0x25, 0x4b, 0xf3, 0x53, 0xb7, 0x73, 0x30, 0x4e, 0xec])
    dec_msg = aes.decrypt(bytes.fromhex('0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329'), mode='CTR')
    print(f'example_msg_2 is {dec_msg}')

    aes = AES(bytes.fromhex('36f18357be4dbd77f050515c73fcf9f2'),
              [0x77, 0x0b, 0x80, 0x25, 0x9e, 0xc3, 0x3b, 0xeb, 0x25, 0x61, 0x35, 0x8a, 0x9f, 0x2d, 0xc6, 0x17])
    dec_msg = aes.decrypt(bytes.fromhex('e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451'), mode='CTR')
    print(f'example_msg_3 is {dec_msg}')


if __name__ == '__main__':
    main()
