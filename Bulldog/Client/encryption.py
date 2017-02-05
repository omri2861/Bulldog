from Crypto.Cipher import AES
from Crypto.Cipher import Blowfish
from Crypto.Cipher import _DES as DES
from Crypto import Random
from struct import pack

__author__ = "Omri Levy"

"""
This module will be the encryption module for the files on Bulldog. It will contain various encryption and decryption
functions, according to the types which are used by Bulldog.

These function will be private, and will be accessed by two functions in this module: encrypt and decrypt. Their usage
will allow choosing the encryption type, key, and so on....

NOTE: This module needs PyCrypto installed to work properly.
"""

DEFAULT_IV = "0000000000000000"
TRIPLE_DES = 1
AES_ENCRYPTION = 2
BLOWFISH = 3
CHUNK_SIZE = 512
PADDING = '\x00'


class Suite(object):
    def __init__(self, mode, key, iv, key2=None, key3=None):
        """

        :param mode:
        :param key:
        :param iv:
        """
        if mode is AES_ENCRYPTION:
            self.suite = AES.new(key, AES.MODE_CBC, iv)
            self.encrypt = self.suite.encrypt
            self.decrypt = self.suite.decrypt
            self.BLOCK_SIZE = 16
        elif mode is BLOWFISH:
            self.suite = Blowfish.new(key, AES.MODE_CBC, iv)
            self.encrypt = self.suite.encrypt
            self.decrypt = self.suite.decrypt
            self.BLOCK_SIZE = 8
        elif mode is TRIPLE_DES:
            if key3 is None:
                key3 = key
            self.BLOCK_SIZE = 8
            self.suites = [
                DES.new(key, DES.MODE_CBC, iv),
                DES.new(key2, DES.MODE_CBC, iv),
                DES.new(key3, DES.MODE_CBC, iv)
            ]

            def encrypt(data):
                cipher = self.suites[0].encrypt(data)
                cipher = self.suites[1].decrypt(cipher)
                cipher = self.suites[2].encrypt(cipher)
                return cipher

            def decrypt(data):
                cipher = self.suites[0].decrypt(data)
                cipher = self.suites[1].encrypt(cipher)
                cipher = self.suites[2].decrypt(cipher)
                return cipher

            self.encrypt = encrypt
            self.decrypt = decrypt
# TODO: While writing the functions, the documentation should be changed to meet each encryption type's requirements.


def add_padding(text):
    """
    Adds padding to the given string so that it's length is dividable by 16 and can be encrypted.
    :param text: str. The string which should be padded
    :return: str. The string with padding.
    """
    padding_length = 16 - (len(text) % 16)
    padded_text = text
    while padding_length != 0:
        padded_text += PADDING
        padding_length -= 1
    return padded_text


def encrypt_file_test():
    """
    This function is a temporary function which meant to test the encryption of files.
    :return: None
    """
    in_file = r"F:\Cyber\Bulldog\src\README.txt"
    out_file = r"F:\Cyber\Bulldog\src\README-encrypted.txt"
    suite = Suite(AES_ENCRYPTION, 'omrithekingofall', DEFAULT_IV)
    with open(in_file, mode='rb') as input_file:
        with open(out_file, mode='wb') as output:
            chunk = input_file.read(CHUNK_SIZE)
            while len(chunk) != 0:
                chunk = add_padding(chunk)
                cipher = suite.encrypt(chunk)
                output.write(cipher)
                chunk = input_file.read(CHUNK_SIZE)


def decrypt_file_test():
    """
    This function is a temporary function which meant to test the decryption of files.
    :return: None
    """
    in_file = r"F:\Cyber\Bulldog\src\README-encrypted.txt"
    out_file = r"F:\Cyber\Bulldog\src\README-decrypted.txt"
    suite = Suite(AES_ENCRYPTION, 'omrithekingofall', DEFAULT_IV)
    with open(in_file, mode='rb') as input_file:
        with open(out_file, mode='wb') as output:
            chunk = input_file.read(CHUNK_SIZE)
            while len(chunk) != 0:
                cipher = suite.decrypt(chunk)
                cipher = cipher.rstrip(PADDING)
                output.write(cipher)
                chunk = input_file.read(CHUNK_SIZE)


def main():
    encrypt_file_test()
    decrypt_file_test()

if __name__ == '__main__':
    main()
