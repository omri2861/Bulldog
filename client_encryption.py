import os
import multiprocessing
import sys
from PyQt4 import QtGui, QtCore
from Bulldog.Client import GUI, encryption
from Bulldog import networking
from pickle import dumps, loads
import socket

"""
This is the program which should be executed when the client selects a few files and wants to encrypt them with bulldog.
"""

SERVER_IP = "127.0.0.1"
SERVER_PORT = 8080
SERVER_ADDRESS = SERVER_IP, SERVER_PORT
DEFAULT_TIMEOUT = 2
IV_SIZES = {
    1: 16,
    2: 8,
    3: 8
}
KEY_SIZES = {
    1: 16,
    2: 16,
    3: 24
}
BAND_WIDTH = 1024


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
    """
    This function will launch a Bulldog encryption window- A window which confirms the files requested, username and
    password.
    :param encryption_path:
    :param parent_input:
    :return:
    """
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

    # perform the actions which doesn't depend on the configuration window- create a connection:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.settimeout(DEFAULT_TIMEOUT)
    try:
        server.connect(SERVER_ADDRESS)
        print "Connected to server."
    except socket.timeout:
        print "Couldn't connect to server."
        sys.exit(1)
        # TODO: Handle server disconnection.

    # TODO: Open an AES stream using RSA:
    pass

    # Receive the task object:
    task = parent_conn.recv()
    task = loads(task)

    # wait until the configuration window is done:
    config_window.join()
    child_conn.close()

    if task is None:
        sys.exit()

    # TODO:Confirm username and password:
    login_msg = networking.BDTPMessage(operation=networking.OPERATIONS['login'], status=0,
                                       data=task.username+"\r\n"+task.password)
    server.send(login_msg.pack())
    server_response = networking.receive_full_message(server)
    user_id = int(server_response.get_data())

    # Start encrypting:
    paths_to_encrypt = get_directory_files_list(task.path)
    for path in paths_to_encrypt:
        iv = '0' * IV_SIZES[task.method]
        key = os.urandom(KEY_SIZES[task.method])
        new_file = networking.EncryptedFile(task.method, iv, key)

        add_file_msg = networking.BDTPMessage(operation=networking.OPERATIONS['add file'], status=0,
                                              data=new_file.pack())
        server.send(add_file_msg.pack())

        server_response = networking.receive_full_message(server)

        file_id = int(server_response.get_data())
        encryption.encrypt_file(path, task.method, user_id, file_id, iv, key)

    # TODO:Finally, remove the original files:
    pass

    # Logout from the server:
    logout_msg = networking.BDTPMessage(operation=networking.OPERATIONS['logout'], status=0, data='')
    server.send(logout_msg.pack())
    server.close()

if __name__ == '__main__':
    main()
