import os
import multiprocessing
from multiprocessing.reduction import ForkingPickler
import StringIO
import sys
from PyQt4 import QtGui, QtCore
from Bulldog import GUI, encryption, networking
from pickle import dumps, loads
import socket

"""
This is the program which should be executed when the client selects a few files and wants to encrypt them with bulldog.
"""

SERVER_IP = "127.0.0.1"
SERVER_PORT = 8080
SERVER_ADDRESS = SERVER_IP, SERVER_PORT
DEFAULT_TIMEOUT = 2
# The key and IV sizes according to the encryption methods (by their number)
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
NO_TASK_MSG = "Error: Did not receive task from subprocess."


def get_directory_files_list(dir_path):
    """
The function will iterate over all of the files and subdirectories in the given path, and will return a list of all
the files it contains and its sub directories. If the given path is a file, it will be returned in a list.
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
This function is meant to be executed as a different process (not a thread as GUI only works in main thread) and is
expected to return its result pickled through the parent input instead of a return value.
    :param encryption_path: The path to the file or directory which should be encrypted.
    :param parent_input: A writable buffer. The function will return it's result pickled through this buffer/ stream.
    :return: A Task object- which contains the details of the user encryption request.
    """
    app = QtGui.QApplication(sys.argv)

    window = GUI.EncryptionWindow(encryption_path)
    window.show()

    app.exec_()

    task = window.task
    parent_input.send(dumps(task))
    parent_input.close()


def find_username_and_password(parent_input):
    """
This function will launch a Bulldog login window- A window which confirms the username and
password.
This function is meant to be executed as a different process (not a thread as GUI only works in main thread) and is
expected to return its result pickled through the parent input instead of a return value.
    :param parent_input: A writable buffer. The function will return it's result through this buffer.
    :return: None. The result is sent through the parent input, as login data in the same format of BDTPMessage.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect(SERVER_ADDRESS)

    app = QtGui.QApplication(sys.argv)

    GUI.login_failed_popup()
    window = GUI.LoginWindow(server_socket)
    window.show()

    app.exec_()

    username = window.correct_username
    password = window.correct_password

    logout_msg = networking.BDTPMessage(operation=networking.OPERATIONS['logout'], status=0, data='')
    server_socket.send(logout_msg.pack())
    server_socket.close()

    if window.user_id != -1:
        parent_input.send(username + networking.DATA_SEP + password)
        parent_input.close()
    else:
        parent_input.send("")


def start_login_subprocess():
    """
    This function will start the find_username_and_password function as a different subprocess.
    :return: int. The user id if logged in successfully. -1 if an error occurred or the user chose to abort the task.
    """
    child_conn, parent_conn = multiprocessing.Pipe(duplex=True)
    login_subprocess = multiprocessing.Process(target=find_username_and_password, args=(child_conn,))
    login_subprocess.start()

    login_subprocess.join()

    login_data = parent_conn.recv()
    username, password = tuple(login_data.split(networking.DATA_SEP))
    return username, password


def perform_login(server_socket, username, password):
    """
    This function will send a login message to the server and will return the user's id as a result.
    :param server_socket: The socket of the server which should be logged in to.
    :param username: The username of the user.
    :param password: The password of the user.
    :return: int. The user's id returned by the server, extracted from the message.
    """
    login_data = username + networking.DATA_SEP + password
    login_msg = networking.BDTPMessage(operation=networking.OPERATIONS['login'], status=0,
                                       data=login_data)
    server_socket.send(login_msg.pack())
    server_response = networking.receive_full_message(server_socket)
    user_id = int(server_response.get_data())

    return user_id


def main():
    """
    The main function of the program. Will execute the GUI and request the server to encrypt the file.
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
        raise Exception(NO_TASK_MSG)

    user_id = perform_login(server, task.username, task.password)

    if user_id == -1:
        username, password = start_login_subprocess()
        user_id = perform_login(server, username, password)

    # Even after the login window confirmed the username and password, the user id is bad, indicating that the user
    # canceled the process or an error occurred:
    if user_id == -1:
        # TODO: handle login error/ cancellation
        pass

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
