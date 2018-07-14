import string

import collections

from Week1.helpers import strxor


class Hacker:
    def __init__(self, cipher_texts, key_len):
        self.cipher_texts = cipher_texts
        self.key_len = key_len

    def two_time_pad_attack(self):
        key = [None] * self.key_len
        known_key_positions = set()
        for current_index, current_ctext in enumerate(self.cipher_texts):
            counter = collections.Counter()
            for index, ctext in enumerate(self.cipher_texts):
                if current_index != index:
                    ctext0_xor_ctext1 = strxor(current_ctext, ctext)
                    for indexOfChar, char in enumerate(ctext0_xor_ctext1):
                        str_char = chr(char)
                        if str_char in string.printable and str_char.isalpha():
                            counter[indexOfChar] += 1

            known_space_indexes = []
            for indexOfChar, value in counter.items():
                if value >= 7:
                    known_space_indexes.append(indexOfChar)

            xor_with_spaces = strxor(current_ctext, b'\x20' * self.key_len)
            for index in known_space_indexes:
                # Store the key's value at the correct position
                key[index] = xor_with_spaces[index]
                # Record that we known the key at this position
                known_key_positions.add(index)

        key = b''.join(bytes([val]) if val is not None else b'\x00' for val in key)
        return known_key_positions, key
