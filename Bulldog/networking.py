import struct

"""
This module will contain all the objects needed for the communication between the server and the client.
"""

OPERATIONS = {
    "login": "LIN\x00",
    "logout": "LOUT",
    "add file": "ADD\x00",
    "decrypt file": "DEC\x00",
    "create connection": "CON\x00"
}
BAD_METHOD_MSG = "Invalid method: Method should be a number in the range of 1-3."


class EncryptedFile(object):
    """
    This class will represent a file which should be encrypted by the client. The client will use this class to send the
    data of a file to the server, and the server will use it to easily store it in the database.
    properties:
    method- int. The encryption method. A number which varies from 0-2
    iv- str. The initializing vector for the encryption.
    key- str. The key used for the encryption.
    """
    FORMATS = {
        1: "h16s16s",
        2: "h8s16s",
        3: "h8s24s"
    }

    def __init__(self, method, iv, key):
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
        cls.method, cls.iv, cls.key = struct.unpack(cls.FORMATS[method], raw_string)
        return cls

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
    """
    PROTOCOL = "4shh%ds"
    PROTOCOL_FIELDS = ('operation', 'status', 'flags', 'data')
    HEADER_LENGTH = 4 + 2 + 2

    def __init__(self, **kwargs):
        for key in self.PROTOCOL_FIELDS:
            if key not in kwargs.keys():
                raise ValueError("Note: Please provide the '%s' field to the message. " % key)
        for protocol_field in self.PROTOCOL_FIELDS:
            self.__setattr__(protocol_field, kwargs[protocol_field])
        self.data = str(self.data)

    def pack(self):
        """
        This method will pack the protocol attributes and values to a string as described by the protocol, ready to be
        sent through the socket.
        """
        return struct.pack(self.PROTOCOL % len(self.data), self.operation, self.status, self.flags, self.data)

    @classmethod
    def unpack(cls, raw_msg):
        """
        This method work like the 'struct.unpack' method. It will unpack the given string into the class attributes.
        """
        data_len = len(raw_msg) - cls.HEADER_LENGTH
        if data_len < 0:
            raise ValueError("This is not a BDTP Message. Note: It is likely that the message is an empty string due to"
                             "a server error and the socket short timeout.")
        cls.operation, cls.status, cls.flags, cls.data = struct.unpack(cls.PROTOCOL % data_len, raw_msg)
        return cls

    def __str__(self):
        """
        This method will return a string which describes the message attributes. Note: This string is not meant to be
        sent through a socket, and cannot be reconstructed to a class.
        This string should print the message and it's attributes clearly, mainly for debugging and logging.
        """
        description = "Operation: %s\n" % self.operation
        description += "Status Code: %d\n" % self.status
        description += "Flags: %d\n" % self.flags
        description += "Data: \n%s\n" % self.data
        return description


def main():
    """
    Add Documentation here
    """
    pass  # Add Your Code Here


if __name__ == '__main__':
    main()