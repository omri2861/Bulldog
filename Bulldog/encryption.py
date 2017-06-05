from Crypto.Cipher import AES
from Crypto.Cipher import Blowfish
from Crypto.Cipher import _DES as DES
import os
import struct

__author__ = "Omri Levy"

"""
This module will be the encryption module for the files on Bulldog. It will contain various encryption and decryption
functions, according to the types which are used by Bulldog.

These function will be private, and will be accessed by two functions in this module: encrypt_file() and decrypt_file().
Their usage will allow choosing the encryption type, _key, and so on....

NOTE: This module needs PyCrypto installed to work properly.
"""

MODE_AES = 1
MODE_BLOWFISH = 2
MODE_TDES = 3
CHUNK_SIZE = 256
PADDING = 'o'
ENCRYPTED_FILE_ENDING = ".bef"
MAGIC_NUMBER = 0x286
HEADERS_FORMAT = "hxxixxi"
HEADER_SIZE = 16

# TODO: Remove testing when done.


class Suite(object):
    """
    This suite will simplify the use of file encryption by creating an easy syntax.
    """
    def __init__(self, method, iv=None, key=None):
        """
        The init function which will set the iv and key according to the given encryption method. It will also set the
        'encrypt' and 'decrypt' class methods.
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
        :return: tuple. (iv, key). The iv and key used by the suit to encrypt\decrypt files.
        """
        return self._iv, self._key


def add_padding(text, block_size=16):
    """
    Adds padding to the given string so that it's length is dividable by 16 and can be encrypted.
    :param text: str. The string which should be padded
    :param block_size: The _size of each block in the encryption.
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


def get_file_header(user_id, file_id):
    """
    This function will receive the raw file_id and user_id numbers and will return a byte array of the encrypted file
    headers which could be written directly into the file.
    :param user_id: int. The id of the user which encrypts the file.
    :param file_id: int. The file id number.
    :return: byte array. The headers which should be written to the encrypted file.
    """
    return struct.pack(HEADERS_FORMAT, MAGIC_NUMBER, user_id, file_id)


def encrypt_file(file_path, method, user_id, file_id, iv=None, key=None):
    """
Encrypts the given file and returns the iv and key of the encryption.
This function allows much easier usage of the suite and the entire module, as it fully and safely encrypts a file using
one function only.
Note: This function does not delete the original decrypted file.
    :param file_path: str. The path to the file which should be encrypted.
    :param method: int. The encryption method which should be used (As a flag constant).
    :param user_id: int. The id of the user which encrypts the file.
    :param file_id: int. The id of the file being encrypted.
    :param iv: str. optional, in case the program which uses the suit wants to select the iv itself, instead of letting
    the suite to do it by itself, or when the suite is made to decrypt.
    :param key: str. optional, in case the program which uses the suit wants to select the key itself, instead of
    letting the suite to do it by itself, or when the suite is made to decrypt.
    :return: tuple. (iv, key) which were used to encrypt the file (needed when the function randomly chooses the key and
    iv and they are not given).
    """

    out_file = file_path + ENCRYPTED_FILE_ENDING

    if iv is not None and key is not None:
        suite = Suite(method=method, iv=iv, key=key)
    else:
        suite = Suite(method)

    with open(out_file, mode='wb') as output:
        headers = get_file_header(user_id, file_id)
        output.write(headers)
        with open(file_path, mode='rb') as input_file:
            chunk = input_file.read(CHUNK_SIZE)
            while len(chunk) != 0:
                if len(chunk) < CHUNK_SIZE:
                    chunk = add_padding(chunk, suite.BLOCK_SIZE)
                cipher = suite.encrypt(chunk)
                output.write(cipher)
                chunk = input_file.read(CHUNK_SIZE)

    return suite.get_iv_and_key()


def scan_file_header(file_path):
    """
    This function will return the file id and user id as saved in the server.
    :param file_path: The path to the file which should be read.
    :return: tuple(user_id, file_id). Both are of type int. If the operation wasn't successfull, both numbers will be
    set to -1.
    """
    operation_failed = (-1, -1)
    if not (os.path.isfile(file_path) and file_path.endswith(ENCRYPTED_FILE_ENDING)):
        return operation_failed

    input_file = open(file_path, 'rb')
    magic_number, user_id, file_id = struct.unpack(HEADERS_FORMAT, input_file.read(HEADER_SIZE))
    input_file.close()

    if MAGIC_NUMBER != magic_number:
        return operation_failed

    return user_id, file_id


def decrypt_file(filename, method, iv, key):
    """
    This function will decrypt the selected file, using the decryption suite. This function is using the suite, but
    allows an easier usage of it, as it fully decrypts a file with one function.
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
            input_file.read(HEADER_SIZE)  # Getting rid of the unneeded header
            chunk = input_file.read(CHUNK_SIZE)
            while len(chunk) != 0:
                cipher = suite.decrypt(chunk)
                if len(cipher) < CHUNK_SIZE:
                    cipher = cipher.rstrip(PADDING)
                output.write(cipher)
                chunk = input_file.read(CHUNK_SIZE)

    # TODO: Strip padding
