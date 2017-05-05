import socket
from pickle import loads

"""
This program will launch the database, and will turn the connection based commanding method to a shell. If this works,
it will be very easy to integrate the database with the server.
"""

PORT = 7091
COLUMN_SEPARATOR = ' | '
ERROR_MSG = "Error- Bad command:\n"
LINE_START = ">>> "
BAND_WIDTH = 1024
EXIT = "exit"
EXIT_WITHOUT_COMMIT = "quit"
COMMIT = "commit"


def main():
    """
    The main function of the program.
    :return: None
    """
    database = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    database.connect(('localhost', PORT))

    while True:
        command = raw_input(LINE_START)
        database.send(command)

        response = loads(database.recv(BAND_WIDTH))

        if command in (EXIT, EXIT_WITHOUT_COMMIT):
            print response
            break

        if type(response) is list:
            print repr(response)
            for row in response:
                print COLUMN_SEPARATOR.join([str(item) for item in row])
        elif type(response) is str:
            print response
        elif response:
            print "\nRequest successfull.\n"
        else:
            print "\nRequest not successfull: Syntax Error\n"

if __name__ == '__main__':
    main()
