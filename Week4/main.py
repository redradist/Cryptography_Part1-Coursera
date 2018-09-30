import urllib.request, urllib.error, urllib.parse
import sys

from bitstring import BitArray

target_url = 'http://crypto-class.appspot.com/po?er='
# --------------------------------------------------------------
# padding oracle
# --------------------------------------------------------------
def padding_oracle_query(query):
    query_url = target_url + urllib.parse.quote(query)  # Create query URL
    req = urllib.request.Request(query_url)  # Send HTTP request to server
    try:
        f = urllib.request.urlopen(req)  # Wait for response
        return True         # good padding
    except urllib.error.HTTPError as e:
        print("We got: %d" % e.code)  # Print response code
        if e.code == 404:
            return True     # good padding
        else:
            return False    # bad padding


def bxor(b1, b2): # use xor for bytes
    parts = []
    for b1, b2 in zip(b1, b2):
        parts.append(bytes([b1 ^ b2]))
    return b''.join(parts)


def lshift(msg, num):
    msg = BitArray(hex=msg.hex())
    msg <<= num * 8
    msg = msg.tobytes()
    return msg


if __name__ == "__main__":
    start_index = 0
    finish_index = 256
    block_size = 16
    cipher_text = bytes.fromhex('f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4')
    num_bytes = len(cipher_text)

    complete_msg_text = bytes()
    msg_text = bytes()
    handled_bytes = 0
    guess_byte = start_index
    while handled_bytes < (num_bytes - block_size):
        while guess_byte < finish_index:
            print('>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>')
            print(f'Test guess_byte = {guess_byte}')
            guess_msg_text = bytes([guess_byte]) + msg_text
            i = len(guess_msg_text)
            while i < num_bytes:
                guess_msg_text = bytes([0]) + guess_msg_text
                i += 1

            pad_text = bytes()
            i = 0
            pad_num = handled_bytes + 1
            while i < pad_num:
                pad_text = bytes([pad_num]) + pad_text
                i += 1
            while i < num_bytes:
                pad_text = bytes([0]) + pad_text
                i += 1

            assert len(cipher_text) == len(guess_msg_text)
            assert len(guess_msg_text) == len(pad_text)
            guess_msg_text = lshift(guess_msg_text, block_size)
            pad_text = lshift(pad_text, block_size)
            mod_text = bxor(guess_msg_text,
                            pad_text)
            updated_cipher_text = bxor(cipher_text, mod_text)
            print(f'Guess message text is   {guess_msg_text.hex()}')
            print(f'Pad text is             {pad_text.hex()}')
            print(f'Modified text is        {mod_text.hex()}')
            print(f'Original cipher text is {cipher_text.hex()}')
            print(f'Updated cipher text is  {updated_cipher_text.hex()}')
            # print(f'Decrypted message is {str(guess_msg_text.decode("utf-8"))}')
            result = padding_oracle_query(updated_cipher_text.hex())
            if result:
                msg_text = bytes([guess_byte]) + msg_text
                handled_bytes += 1
                guess_byte = start_index
                if len(msg_text) == block_size:
                    complete_msg_text = msg_text + complete_msg_text
                    cipher_text = cipher_text[0:len(cipher_text)-len(msg_text)]
                    num_bytes -= len(msg_text)
                    handled_bytes = 0
                    guess_byte = start_index
                    msg_text = bytes()
                break
            else:
                guess_byte += 1
            print('<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<')
        else:
            guess_byte = int(msg_text[0])
            guess_byte += 1
            msg_text = msg_text[1:]
            handled_bytes -= 1
    plain_text = complete_msg_text.decode('utf-8')
    print(f'Decrypted message is {str(plain_text)}')
    assert plain_text == 'The Magic Words are Squeamish Ossifrage'
