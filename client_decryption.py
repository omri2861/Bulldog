from Bulldog import networking, GUI, encryption
import sys
import os
import multiprocessing

"""
This is the main decryption program of Bulldog. It should be launched when the user wants to decrypt file/s.
"""


SERVER_IP = "127.0.0.1"
SERVER_PORT = 8080
SERVER_ADDRESS = SERVER_IP, SERVER_PORT
DEFAULT_TIMEOUT = 5
ENCRYPTED_FILES_ENDING = ".bef"


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


def find_username_and_password(parent_input, encrypter_id):
    """
This function will launch a Bulldog login window- A window which confirms the username and
password.
This function is meant to be executed as a different process (not a thread as GUI only works in main thread) and is
expected to return its result pickled through the parent input instead of a return value.
    :param parent_input: A writable buffer. The function will return it's result through this buffer.
    :param encrypter_id: The id of the user which encrypted the file as saved in the server.
    :return: None. The result is sent through the parent input, as login data in the same format of BDTPMessage.
    """
    server_socket = networking.BulldogSocket()
    server_socket.connect(SERVER_ADDRESS)

    app = GUI.QtGui.QApplication(sys.argv)

    window = GUI.LoginWindow(server_socket)
    window.show()

    app.exec_()

    username = window.correct_username
    password = window.correct_password

    logout_msg = networking.BDTPMessage(operation=networking.OPERATIONS['logout'],
                                        status=networking.STATUS_CODES['request'], data='')
    server_socket.send(logout_msg.pack())
    server_socket.close()

    if window.user_id == encrypter_id:
        parent_input.send(username + networking.DATA_SEP + password)
        parent_input.close()
    elif window.user_id != -1:
        # TODO: handle wrong user login
        print "Logged in to the system, but not as the person who encrypted."
        find_username_and_password(parent_input, encrypter_id)
    else:
        parent_input.send("")
        parent_input.close()


def start_login_subprocess(user_id):
    """
    This function will start the find_username_and_password function as a different subprocess.
    :param user_id: int. The id of the user which locked the files which should be decrypted.
    :return: int. The user id if logged in successfully. -1 if an error occurred or the user chose to abort the task.
    """
    child_conn, parent_conn = multiprocessing.Pipe(duplex=True)
    login_subprocess = multiprocessing.Process(target=find_username_and_password, args=(child_conn, user_id))
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
                                       status=networking.STATUS_CODES['request'],data=login_data)
    server_socket.send(login_msg.pack())
    server_response = server_socket.smart_recv()
    user_id = int(server_response.get_data())

    return user_id


def main():
    """
    The main function of the program. Will decrypt the given files in the system arguments.
    :return: None
    """
    paths_to_decrypt = [path for path in get_directory_files_list(sys.argv[1]) if path.endswith(ENCRYPTED_FILES_ENDING)]

    # TODO: Make sure all files has the same user_id
    user_id, file_id = encryption.scan_file_header(paths_to_decrypt[0])

    username, password = start_login_subprocess(user_id)

    server = networking.BulldogSocket()
    server.connect(SERVER_ADDRESS)

    user_id = perform_login(server, username, password)

    for file_path in paths_to_decrypt:
        user_id, file_id = encryption.scan_file_header(file_path)
        request_data = "%d%s%d" % (user_id, networking.DATA_SEP, file_id)
        decryption_request = networking.BDTPMessage(networking.OPERATIONS['decrypt file'],
                                                    status=networking.STATUS_CODES['request'], data=request_data)
        server.send(decryption_request.pack())
        response = server.smart_recv()
        file_info = networking.EncryptedFile.unpack(response.get_data())
        encryption.decrypt_file(file_path, file_info.method, file_info.iv, file_info.key)

    # Logout from the server:
    logout_msg = networking.BDTPMessage(operation=networking.OPERATIONS['logout'],
                                        status=networking.STATUS_CODES['request'], data='')
    server.send(logout_msg.pack())
    server.close()





if __name__ == '__main__':
    main()
