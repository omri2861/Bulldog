import struct

"""
This module will contain all the objects needed for the communication between the server and the client.
"""

OPERATIONS = {
    "login": "LIN",
    "logout": "LOUT",
    "add file": "ADD",
    "decrypt file": "DEC",
    "create connection": "CON"
}


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
        cls.operation, cls.status, cls.flags, cls.data = struct.unpack(cls.PROTOCOL % data_len, raw_msg)

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