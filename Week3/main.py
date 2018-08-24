import sys

from itertools import chain, islice
from pycodec.hash.sha2 import SHA2


if __name__ == '__main__':
    prev_sha256 = None
    with open('./data/6.1.intro.mp4', 'rb') as bigfile:
        print('File is opened !!')
        data = b''.join(bigfile.readlines())
        number_of_chunks = len(data) // 1024
        if len(data) % 1024 != 0:
            number_of_chunks += 1
        print(f'number_of_chunks = {number_of_chunks}')
        i = 0
        for chunk in (data[i*1024:(i+1)*1024] for i in reversed(range(0, number_of_chunks))):
            print(f'iteration number {i}')
            if prev_sha256 is None:
                prev_sha256 = SHA2.hash_sha256(chunk)
            else:
                msg = chunk + prev_sha256
                prev_sha256 = SHA2.hash_sha256(msg)
            i += 1
    print(f'h0 is {prev_sha256.hex()}')
