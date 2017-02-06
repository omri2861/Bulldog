from Crypto.Cipher import AES
from Crypto.Cipher import Blowfish
from Crypto.Cipher import _DES as DES
import os

__author__ = "Omri Levy"

"""
This module will be the encryption module for the files on Bulldog. It will contain various encryption and decryption
functions, according to the types which are used by Bulldog.

These function will be private, and will be accessed by two functions in this module: encrypt_file() and decrypt_file().
Their usage will allow choosing the encryption type, _key, and so on....

NOTE: This module needs PyCrypto installed to work properly.
"""

MODE_TDES = 1
MODE_AES = 2
MODE_BLOWFISH = 3
CHUNK_SIZE = 256
PADDING = '\x00'
INFO_TEMPLATE = "iv:%s\r\nkey:%s\r\n"
INFO_PATTERN = "iv:(.+)\r\nkey:(.+)\r\n"
ENCRYPTED_FILE_ENDING = ".bef"


class Suite(object):
    """
    This suite will simplify the use of file encryption by creating an easy syntax.
    """
    def __init__(self, method, iv=None, key=None):
        """
        :param method: int. The encryption method which should be used (flag\ constant).
        :param key: str. The encryption key which should be used.
        :param iv: str. The initializing vector used for the block chain.
        """
        self.method = method

        if method is MODE_AES:
            self.BLOCK_SIZE = 16
            self.KEY_SIZE = 16

            if key is None and iv is None:
                self._key = os.urandom(self.KEY_SIZE)
                self._iv = '0' * self.BLOCK_SIZE
            else:
                self._key = key
                self._iv = iv

            self.suite = AES.new(self._key, AES.MODE_CBC, self._iv)
            self.encrypt = self.suite.encrypt
            self.decrypt = self.suite.decrypt

        elif method is MODE_BLOWFISH:
            self.BLOCK_SIZE = 8
            self.KEY_SIZE = 16

            if key is None and iv is None:
                self._key = os.urandom(self.KEY_SIZE)
                self._iv = '0' * self.BLOCK_SIZE
            else:
                self._key = key
                self._iv = iv

            self.suite = Blowfish.new(self._key, Blowfish.MODE_CBC, self._iv)
            self.encrypt = self.suite.encrypt
            self.decrypt = self.suite.decrypt
            self.BLOCK_SIZE = 8
        elif method is MODE_TDES:

            self.BLOCK_SIZE = 8
            self.KEY_SIZE = 24

            if key is None and iv is None:
                self._key = os.urandom(self.KEY_SIZE)
                self._iv = '0' * self.BLOCK_SIZE
            else:
                self._key = key
                self._iv = iv

            self.suites = [
                DES.new(self._key[:8], DES.MODE_CBC, self._iv),
                DES.new(self._key[8: 16], DES.MODE_CBC, self._iv),
                DES.new(self._key[16:], DES.MODE_CBC, self._iv)
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

    def get_iv_and_key(self):
        """
        :return: tuple. (iv, key). The iv and key used by the suit.
        """
        return self._iv, self._key


def add_padding(text, block_size=16):
    """
    Adds padding to the given string so that it's length is dividable by 16 and can be encrypted.
    :param text: str. The string which should be padded
    :param block_size: The size of each block in the encryption.
    :return: str. The string with padding.
    """
    if len(text) % block_size == 0:
        return text
    padding_length = block_size - (len(text) % block_size)
    padded_text = text
    while padding_length != 0:
        padded_text += PADDING
        padding_length -= 1
    return padded_text


def encrypt_file(filename, method):
    """
    Encrypts the given file and returns the iv and key of the encryption.
    Note: At this point, the function will create a copy of the encrypted file and will not delete the original file.
    This is because the program is not done, and it might not succeed in decrypting the file, and the encrypted data
    may be lost.
    :param filename: str. The path to the file which should be encrypted.
    :param method: int. The encryption method which should be used (As a flag constant).
    :return: tuple. (iv, key)
    """
    # TODO: add 'os.remove(filename)' at the end of the function when ready.

    out_file = filename + ENCRYPTED_FILE_ENDING

    suite = Suite(method)

    with open(filename, mode='rb') as input_file:
        with open(out_file, mode='wb') as output:
            chunk = input_file.read(CHUNK_SIZE)
            while len(chunk) != 0:
                chunk = add_padding(chunk, suite.BLOCK_SIZE)
                cipher = suite.encrypt(chunk)
                output.write(cipher)
                chunk = input_file.read(CHUNK_SIZE)

    return suite.get_iv_and_key()


def decrypt_file(filename, method, iv, key):
    """
    This function will decrypt the selected file.
    :param filename: str. The path to the file which should be decrypted.
    :param method: int. The decryption method which should be used (flag\ constant).
    :param key: str. The decryption key which should be used.
    :param iv: str. The initializing vector used for the block chain.
    :return: None
    """
    out_file = filename[:filename.index(ENCRYPTED_FILE_ENDING)]
    suite = Suite(method, iv, key)

    with open(filename, mode='rb') as input_file:
        with open(out_file, mode='wb') as output:
            chunk = input_file.read(CHUNK_SIZE)
            while len(chunk) != 0:
                cipher = suite.decrypt(chunk)
                cipher = cipher.rstrip(PADDING)
                output.write(cipher)
                chunk = input_file.read(CHUNK_SIZE)
