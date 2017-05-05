import sqlite3
import sys
import socket
from pickle import dumps

"""
This program will operate the database and communicate with the server.
"""

EXIT = "exit"
EXIT_WITHOUT_COMMIT = "quit"
COMMIT = "commit"
PORT = 7091
BAND_WIDTH = 1024


def execute_altering_command(command, executor, database_connection):
    try:
        executor.execute(command)
        database_connection.commit()
        return True
    except sqlite3.DatabaseError as exception:
        print exception.message
        return exception.message


def execute_selective_command(command, executor):
    try:
        executor.execute(command)
        results = executor.fetchall()
    except sqlite3.OperationalError as exception:
        results = exception.message
    return results


def main():
    """
    The main function of the program.
    :return: None
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('localhost', PORT))
    sock.listen(1)
    manager, addr = sock.accept()
    connection = sqlite3.connect(sys.argv[1])
    cursor = connection.cursor()

    result = False

    while True:
        command = manager.recv(BAND_WIDTH)
        # No need to worry about messages larger than the bandwidth, as it is big enough to contain one sql command.
        # Or at least, so I think. TODO: try sending messages from a few threads and handle it.

        if command == EXIT:
            connection.commit()
            result = True
            break
        elif command == EXIT_WITHOUT_COMMIT:
            result = True
            break
        elif command == COMMIT:
            connection.commit()
            result = True
        elif 'SELECT' in command.upper() or 'PRAGMA' in command.upper():
            result = execute_selective_command(command, cursor)
        else:
            result = execute_altering_command(command, cursor, connection)

        manager.send(dumps(result))

    manager.send(dumps(result))
    manager.close()
    connection.close()


if __name__ == '__main__':
    main()
