import struct
import socket
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto import Random
from pickle import loads, dumps
from os import urandom

"""
This module will contains all the objects needed for the communication between the server and the client.
"""

OPERATIONS = {
    "login": "LIN\x00",
    "logout": "LOUT",
    "add file": "ADD\x00",
    "decrypt file": "DEC\x00",
    "create connection": "CON\x00"
}
BAD_METHOD_MSG = "Invalid method: Method should be a number in the range of 1-3."
BAD_STRING_MSG = "This is not a BDTP Message. Note: It is likely that the message is an empty string due to " \
                             "a server error and the socket short timeout."
BAD_DATA_SIZE_MSG = "It's impossible that the _size of the data is smaller than the actual data. There is an error" \
                         "with the client or server."
BAND_WIDTH = 1024
DATA_SEP = '\r\n'
BAD_STRING_WARNING = "Warning: Empty string given. This could happen because of timing issues, but if re-occurs," \
                     " search for a bug."
PAD = '\x00'
PAD_START = '\xff'


class EncryptedFile(object):
    """
This class will represent a file which should be encrypted by the client. The client will use this class to send the
data of a file to the server, and the server will use it to easily store it in the database.
    properties:
    method- int. The encryption method. A number which varies from 0-2
    iv- str. The initializing vector for the encryption.
    key- str. The key used for the encryption.
    """
    # Formats of packing according to method number:
    FORMATS = {
        1: "h16s16s",
        2: "h8s16s",
        3: "h8s24s"
    }

    def __init__(self, method, iv, key):
        """
Will construct a class from the given properties.
        :param method: int.
        :param iv: str.
        :param key: str.
        """
        if method not in self.FORMATS.keys():
            raise ValueError(BAD_METHOD_MSG)
        self.iv = iv
        self.key = key
        self.method = method

    def pack(self):
        """
        This method will return a string representing the class' properties, ready to be sent through a socket.
        :return: str.
        """
        return struct.pack(self.FORMATS[self.method], self.method, self.iv, self.key)

    @classmethod
    def unpack(cls, raw_string):
        """
        :param raw_string: str. A raw string which contains the object's values according to it's method and formats.
        :return: Constructs an object which fits for the string.
        """
        raw_method = raw_string[0:2]
        method = struct.unpack('h', raw_method)[0]
        method, iv, key = struct.unpack(cls.FORMATS[method], raw_string)
        return cls(method, iv, key)

    def __str__(self):
        """
        :return: str. A string which describes the file's attributes. Note: This string cannot be interpreted (unless
        regex is used) and is meant mainly for debugging. If you want a string which could be sent through socket or
        interpreted, use EncryptedFile.pack()
        """
        description = "Method number: %d\n" % self.method
        description += "Initialization Vector: %s\n" % self.iv
        description += "Key: %s\n" % self.key
        return description


class BDTPMessage(object):
    """
This class will allow easy usage of the BDTP protocol and sending message with it.
The class' properties are identical to the Protocol's fields:
    operation- string. The operation request, represented by four characters (similar to http).
    status- int. The status of the request- whether it was successfull or not (similar to http).
    _size- int. The _size of the data. Note: This property is not given through a parameter, but the objects updates it
    by itself. In this method, if there is a difference between the _size and the actual length of the data, it is
    possible to know that the message hasn't been fully received from the socket, or there's a bug. It is a private
    property, as only the object is allowed to calculate the data size.
    _data- The data of the request which should be transferred through the socket. It is a private method, as the object
    has to update its properties if the data is changed and cannot allow access to anyone.
    """
    PROTOCOL = "4shh%ds"
    HEADER_LENGTH = 4 + 2 + 2

    def __init__(self, operation, status, data):
        self.operation = operation
        self.status = status
        self._data = str(data)
        self._size = len(self._data)

    def pack(self):
        """
        This method will pack the protocol attributes and values to a string as described by the protocol, ready to be
        sent through the socket.
        """
        return struct.pack(self.PROTOCOL % self._size, self.operation, self.status, self._size, self._data)

    @classmethod
    def unpack(cls, raw_msg):
        """
        This method works like the 'struct.unpack' method. It will unpack the given string into the class attributes.
        Note: It will return None if given an empty string.
        :param raw_msg: str.
        """
        if len(raw_msg) == 0:
            print BAD_STRING_WARNING
            return None
        data_len = len(raw_msg) - cls.HEADER_LENGTH
        if data_len < 0:
            print "(length is %d)\n" % len(raw_msg)
            raise ValueError(BAD_STRING_MSG)
        operation, status, size, data = struct.unpack(cls.PROTOCOL % data_len, raw_msg)
        msg = cls(operation=operation, status=status, data=data)
        msg._size = size
        return msg

    def __str__(self):
        """
        This method will return a string which describes the message attributes. Note: This string is not meant to be
        sent through a socket, and cannot be reconstructed to a class.
        This string should print the message and it's attributes clearly, mainly for debugging and logging.
        """
        description = "Operation: %s\n" % self.operation
        description += "Status Code: %d\n" % self.status
        description += "Size: %d\n" % self._size
        description += "Data: \n%s\n" % self._data
        return description

    def set_data(self, data):
        self._data = str(data)
        self._size = len(self._data)

    def get_data(self):
        return self._data

    def get_size(self):
        return self._size


def add_padding(text):
    """
    Adds padding to the given string so that it's length is dividable by 16 and can be encrypted.
    :param text: str. The string which should be padded
    :return: str. The string with padding.
    """
    padding_length = 16 - (len(text) % 16)
    if padding_length == 0:
        return text
    padded_text = text + PAD_START
    padding_length -= 1
    while padding_length != 0:
        padded_text += '\x00'
        padding_length -= 1
    return padded_text


def remove_padding(padded_text):
    """
    This function will remove padding from a message which was padded before sent.
    :param padded_text: str. The padded text.
    :return: str. The text without the padding.
    """
    text = padded_text.rstrip(PAD)
    if text[-1] == PAD_START:
        text = text[:-1]
    return text


class BulldogSocket(object):
    """
    This class allows an easy api usage for an encrypted socket which works with the BDTP protocol, while using the
    socket.socket api.
    This allows full encapsulation for the security (encrypted communication).
    """
    overridden_methods = ('send', 'recv', 'accept', 'connect')
    VALUE_ERROR_MSG = "Error: The object passed to this function is not an existing socket. "
    PARAMETER_ERROR_MSG = "Error: If you wish to specify a socket, please specify the AES key and IV too."

    def __init__(self, existing_socket=None, aes_iv=None, aes_key=None):
        if existing_socket is None:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._encryption_suite = None
            self._decryption_suite = None

        elif isinstance(existing_socket, socket._socketobject):
            self._sock = existing_socket
            if aes_iv is None or aes_key is None:
                raise ValueError(self.PARAMETER_ERROR_MSG)
            self._encryption_suite = AES.new(aes_key, AES.MODE_CBC, aes_iv)
            self._decryption_suite = AES.new(aes_key, AES.MODE_CBC, aes_iv)

        else:
            raise ValueError(self.VALUE_ERROR_MSG)

        socket_callables = [attr for attr in dir(self._sock) if
                            callable(self._sock.__getattribute__(attr))and '__' not in attr and
                            attr not in self.overridden_methods]

        for func_name in socket_callables:
            self.__setattr__(func_name, self._sock.__getattribute__(func_name))

    def connect(self, address):
        # First, connect to the given address:
        self._sock.connect(address)

        # Then, create a connection encrypted with RSA:
        random_generator = Random.new().read
        key = RSA.generate(1024, random_generator)

        public_key = dumps(key.publickey())
        open_connection_msg = BDTPMessage(operation=OPERATIONS['create connection'], status=0, data=public_key)
        self._sock.send(open_connection_msg.pack())

        # Finally, receive the key and iv and create the encryption and decryption suites:
        raw_response = self._sock.recv(BAND_WIDTH)
        raw_response = key.decrypt((raw_response,))
        response = BDTPMessage.unpack(raw_response)
        aes_data = response.get_data()
        iv, key = tuple(aes_data.split(DATA_SEP))
        self._encryption_suite = AES.new(key, AES.MODE_CBC, iv)
        self._decryption_suite = AES.new(key, AES.MODE_CBC, iv)

    def accept(self):
        # First, receive the connecting user
        client, client_address = self._sock.accept()
        raw_request = client.recv(BAND_WIDTH)
        request = BDTPMessage.unpack(raw_request)
        
        # Extract the public key that the user generated:
        public_key = loads(request.get_data())
        aes_key = urandom(16)  # AES key length: 16
        aes_iv = '0' * 16  # AES Block length: 16
        
        # Send the encrypted private key:
        accepting_msg = BDTPMessage(operation=OPERATIONS['create connection'], status=0,
                                    data=aes_iv + DATA_SEP + aes_key)
        accepting_msg = public_key.encrypt(accepting_msg.pack(), 57)[0]  # 57 is meaningless
        client.send(accepting_msg)

        return BulldogSocket(client, aes_iv, aes_key), client_address

    def send(self, msg):
        msg = add_padding(msg)
        self._sock.send(self._encryption_suite.encrypt(msg))

    def recv(self, n_bytes):
        cipher = self._sock.recv(n_bytes)
        text = self._decryption_suite.decrypt(cipher)
        text = remove_padding(text)
        return text

    def smart_recv(self, timeout=-1):
        """
        This method will smartly receive a full message, strip the padding, and return a BDTPMessage object.
        This method eases the usage of the protocol and classes.
        Alternatively, it is still possible to use the provided recv method.
        :param timeout: The of the message receiving.
        :return: BDTPMessage object. The received message.
        """
        if timeout > 0:
            self._sock.settimeout(timeout)

        msg = self.recv(BAND_WIDTH)
        msg = BDTPMessage.unpack(msg)

        if msg is None:
            return None

        full_data = msg.get_data()
        if msg.get_size() == len(full_data):
            return msg
        elif msg.get_size() < len(full_data):
            raise ValueError(BAD_DATA_SIZE_MSG)

        missing_data_size = msg.get_size() - len(full_data)
        while missing_data_size > 0:
            chunk = self.recv(BAND_WIDTH)
            full_data += chunk
            missing_data_size -= len(chunk)

        msg.set_data(full_data)

        self._sock.settimeout(socket.getdefaulttimeout())

        return msg

    def __eq__(self, other):
        if isinstance(other, BulldogSocket):
            return self._sock == other._sock
        elif isinstance(other, socket._socketobject):
            return self._sock == other
        else:
            return False

    def get_real_socket(self):
        """
        This method should return the actual socket object which is used to send the data.
        Warning: This should not be used to send data!!! This method is solely made for select.select function, which
        only receives buffer type objects.
        :return: socket._socketobject of the instance's socket.
        """
        return self._sock
