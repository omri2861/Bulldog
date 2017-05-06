from PyQt4 import QtGui
from Bulldog.client_functions import *
from Bulldog import encryption
from pickle import dumps, loads

"""
This is the main encryption program of Bulldog. It should be launched when the user wants to encrypt file/s.
"""

# The key and IV sizes according to the encryption methods (by their number):
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
    server_socket = networking.BulldogSocket()
    server_socket.connect(SERVER_ADDRESS)

    app = QtGui.QApplication(sys.argv)

    GUI.login_failed_popup()
    window = GUI.LoginWindow(server_socket)
    window.show()

    app.exec_()

    username = window.correct_username
    password = window.correct_password

    logout_msg = networking.BDTPMessage(operation=networking.OPERATIONS['logout'],
                                        status=networking.STATUS_CODES['request'], data='')
    server_socket.send(logout_msg.pack())
    server_socket.close()

    if window.user_id != -1:
        parent_input.send(username + networking.DATA_SEP + password)
        parent_input.close()
    else:
        parent_input.send("")
        parent_input.close()


@GUI.blocking_operation
def encrypt_files(task, user_id, server):
    """
    This function will encrypt all the files which are in the path in the task object.
    :param task: The object which specifies the required information to perform the encryption.
    :type task: Task
    :param user_id: The id of the user which encrypts the files.
    :type user_id: int
    :param server: The server socket.
    :type server: networking.BulldogSocket
    :return: None
    """
    paths_to_encrypt = get_directory_files_list(task.path)

    for path in paths_to_encrypt:
        iv = '0' * IV_SIZES[task.method]
        key = os.urandom(KEY_SIZES[task.method])
        new_file = networking.EncryptedFile(task.method, iv, key)

        add_file_msg = networking.BDTPMessage(operation=networking.OPERATIONS['add file'],
                                              status=networking.STATUS_CODES['request'], data=new_file.pack())
        server.send(add_file_msg.pack())

        server_response = server.smart_recv()

        file_id = int(server_response.get_data())
        encryption.encrypt_file(path, task.method, user_id, file_id, iv, key)

        os.remove(path)


@GUI.error_handler
def main():
    """
    The main function of the program. Will execute the GUI and request the server to encrypt the file.
    :return: None
    """
    encryption_path = sys.argv[1]

    # Connect to the server:
    server = connect_to_server(CONNECTING_TO_SERVER_TEXT)
    if server is None:
        sys.exit(-1)

    # Start the encryption window subprocess:
    child_conn, parent_conn = multiprocessing.Pipe(duplex=True)
    config_window = multiprocessing.Process(target=launch_config_window, args=(encryption_path, child_conn))
    config_window.start()

    # Receive the task object:
    task = parent_conn.recv()
    task = loads(task)

    # wait until the configuration window is done:
    config_window.join()
    child_conn.close()

    if task is None:
        raise Exception(NO_TASK_MSG)

    # Login to the server:
    user_id = perform_login(server, task.username, task.password)
    if user_id == -1:
        username, password = start_login_subprocess(find_username_and_password)
        user_id = perform_login(server, username, password)

    if user_id == -1:
        # Even after the login window confirmed the username and password, the user id is bad, indicating that the user
        # canceled the process or an error occurred:
        server.close()
        sys.exit()

    # Start encrypting:
    encrypt_files(text=ENCRYPTING_FILES_MSG, task=task, user_id=user_id, server=server)

    # Logout from the server:
    logout_msg = networking.BDTPMessage(operation=networking.OPERATIONS['logout'],
                                        status=networking.STATUS_CODES['request'], data='')
    server.send(logout_msg.pack())
    server.close()

if __name__ == '__main__':
    main()
