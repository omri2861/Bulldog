from Bulldog.Client import GUI, encryption
from PyQt4 import QtCore, QtGui
import sys
import os

"""
This is the program which should be executed when the client selects a few files and wants to encrypt them with bulldog.
"""

DEFAULT_PATH = r"F:\Cyber\Bulldog\src"


def get_directory_files_list(dir_path):
    """
    :param dir_path: The path of the directory which should be listed.
    :return: A list of strings containing the directory's files' full path.
    """
    result = []
    for file_name in os.listdir(dir_path):
        file_path = os.path.join(dir_path, file_name)
        if os.path.isdir(file_path):
            result += get_directory_files_list(file_path)
        else:
            result.append(file_path)
    return result


def main():
    """
    The main function of the program.
    :return: None
    """


if __name__ == '__main__':
    main()
