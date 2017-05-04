import sqlite3
import sys

"""
This program will operate the database and communicate with the server.
"""

EXIT = "exit"
EXIT_WITHOUT_COMMIT = "quit"
COLUMN_SEPARATOR = ' | '
ERROR_MSG = "Error- Bad command:\n"
LINE_START = ">>> "
COMMIT = "commit"


def main():
    """
    The main function of the program.
    :return: None
    """
    connection = sqlite3.connect(sys.argv[1])
    cursor = connection.cursor()

    while True:
        command = raw_input(LINE_START)
        if command == EXIT:
            connection.commit()
            sys.exit()
        elif command == EXIT_WITHOUT_COMMIT:
            sys.exit()
        elif command == COMMIT:
            connection.commit()
        else:
            try:
                cursor.execute(command)
                if 'SELECT' in command:
                    results = cursor.fetchall()
                    for row in results:
                        print COLUMN_SEPARATOR.join([str(item) for item in row])
            except sqlite3.OperationalError as exception:
                print ERROR_MSG + exception.message


if __name__ == '__main__':
    main()

