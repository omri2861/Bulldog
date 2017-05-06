import os
import sys
from Bulldog import GUI, networking
from socket import timeout as sock_timeout
from socket import error as sock_error
import multiprocessing

"""
This Module will contain all of the functions which are common for the client decryption and encryption programs.
"""

SERVER_IP = "127.0.0.1"
SERVER_PORT = 8080
SERVER_ADDRESS = SERVER_IP, SERVER_PORT
DEFAULT_TIMEOUT = 2
CONNECTING_TO_SERVER_TEXT = "Connecting to the Bulldog server..."
MAX_CONNECTION_ATTEMPTS = 5
NO_CONNECTION_MSG = "Could not connect to the Bulldog server. Please make sure that your server address is correct," \
                       "or contact the server administrator for troubleshooting."
ENCRYPTING_FILES_MSG = "Encrypting the files..."


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


@GUI.blocking_operation
def connect_to_server():
    """
    This function will connect to the server an return the server socket.
    :return:
    """
    server = networking.BulldogSocket()
    server.settimeout(DEFAULT_TIMEOUT)
    attempts = 0
    while attempts < MAX_CONNECTION_ATTEMPTS:
        try:
            server.connect(SERVER_ADDRESS)
            return server
        except sock_timeout:
            attempts += 1

    raise sock_error(NO_CONNECTION_MSG)


@GUI.error_handler
def start_login_subprocess(func, user_id=None):
    """
    This function will start the find_username_and_password function as a different subprocess.
    :param func: The function which finds the username and password. This callback is transferred as a parameter
    because this function is different between the encryption and the decryption, but the function which activates it
    acts the same.
    :type func: callable
    :param user_id: The id of the user which encrypted the files (if used by the decryption program).
    :return: int. The user id if logged in successfully. -1 if an error occurred or the user chose to abort the task.
    """
    child_conn, parent_conn = multiprocessing.Pipe(duplex=True)
    if user_id is None:
        login_subprocess = multiprocessing.Process(target=func, args=(child_conn,))
    else:
        login_subprocess = multiprocessing.Process(target=func, args=(child_conn, user_id))
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
    login_msg = networking.BDTPMessage(operation=networking.OPERATIONS['login'],
                                       status=networking.STATUS_CODES['request'], data=login_data)
    server_socket.send(login_msg.pack())
    server_response = server_socket.smart_recv()
    user_id = int(server_response.get_data())

    return user_id
