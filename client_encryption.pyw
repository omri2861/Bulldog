import os
import multiprocessing
import sys
from PyQt4 import QtGui, QtCore
from Bulldog.Client import GUI, encryption
from pickle import dumps, loads

"""
This is the program which should be executed when the client selects a few files and wants to encrypt them with bulldog.
"""


def get_directory_files_list(dir_path):
    """
    :param dir_path: The path of the directory which should be listed.
    :return: A list of strings containing the directory's files' full path.
    """
    result = []
    if os.path.isfile(dir_path):
        return [dir_path]
    for file_name in os.listdir(dir_path):
        file_path = os.path.join(dir_path, file_name)
        if os.path.isdir(file_path):
            result += get_directory_files_list(file_path)
        else:
            result.append(file_path)
    return result


def launch_config_window(encryption_path, parent_input):

    app = QtGui.QApplication(sys.argv)

    window = GUI.EncryptionWindow(encryption_path)
    window.show()

    app.exec_()

    task = window.task
    parent_input.send(dumps(task))
    parent_input.close()


def main():
    """
    The main function of the program.
    :return: None
    """
    encryption_path = sys.argv[1]

    child_conn, parent_conn = multiprocessing.Pipe(duplex=True)
    config_window = multiprocessing.Process(target=launch_config_window, args=(encryption_path, child_conn))

    # Start the encryption window subprocess:
    config_window.start()

    # perform the actions which doesn't depend on the configuration window:
    task = parent_conn.recv()
    task = loads(task)

    # wait until the configuration window is done:
    config_window.join()
    child_conn.close()

    # if task is None:
        # sys.exit()

    # TODO:Confirm username and password:
    pass

    # TODO: Start encrypting:
    paths_to_encrypt = get_directory_files_list(task.path)
    for path in paths_to_encrypt:
        # TODO: request available file id from server.
        iv, key = encryption.encrypt_file(path, encryption.MODE_AES, 1234, 1234)
        # TODO: upload file data to the server.

    # TODO:Finally, remove the original files:
    pass

if __name__ == '__main__':
    main()
