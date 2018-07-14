#!/usr/bin/python3
import binascii

from Week1.helpers import strxor


class SimpleStreamCipher:
    def __init__(self):
        pass

    def encrypt(self, key, msg):
        ctext = strxor(key, msg)
        print('ciphertext: {}'.format(binascii.hexlify(ctext)))
        return ctext

    def decrypt(self, key, ctext):
        text = strxor(key, ctext)
        print('text: {}'.format(str(text)))
        return ctext
