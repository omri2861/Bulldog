from Crypto.Cipher import Blowfish
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


def blowfish_encrypt(key, iv, data):
    """
    Encrypts the given data using 'Blowfish' algorithm.
    :param key: str. The key of the encryption.
    :param iv: str. As Blowfish is a block cipher, it should be given an IV.
    :param data: The data which should be encrypted.
    :return: str The encrypted data.
    """
    pass


def blowfish_decrypt(key, iv, data):
    """
    Decrypts the given data using 'Blowfish' algorithm.
    :param key: str. The key of the encryption.
    :param iv: str. The iv used for the encryption. Will be used as a checksum.
    :param data: The data which should be decrypted.
    :return: str. The decrypted data.
    """
    pass


def AES_encrypt(key, iv, data):
    """
    Encrypts the given data using 'AES' algorithm.
    :param key: str. The key of the encryption.
    :param iv: str. As Blowfish is a block cipher, it should be given an IV.
    :param data: The data which should be encrypted.
    :return: str The encrypted data.
    """
    pass


def AES_decrypt(key, iv, data):
    """
    Decrypts the given data using 'AES' algorithm.
    :param key: str. The key of the encryption.
    :param iv: str. The iv used for the encryption. Will be used as a checksum.
    :param data: The data which should be decrypted.
    :return: str. The decrypted data.
    """
    pass

# TODO: While writing the functions, the documentation should be changed to meet each encryption type's requirements.
