from Bulldog import encryption
from Bulldog.client_functions import *

"""
This is the main decryption program of Bulldog. It should be launched when the user wants to decrypt file/s.
"""


SERVER_IP = "127.0.0.1"
SERVER_PORT = 8080
SERVER_ADDRESS = SERVER_IP, SERVER_PORT
DEFAULT_TIMEOUT = 2
ENCRYPTED_FILES_ENDING = ".bef"
MAX_CONNECTION_ATTEMPTS = 5
WRONG_USER_TEXT = "You logged successfully to the system, but you are not the user who encrypted this file(s).\n" \
                   "Please login as the user who encrypted this file(s)."
WRONG_USER_TITLE = "Bulldog- Wrong User"
NO_IDENTICAL_ID_TEXT = "Not all of the files selected were encrypted by the same user.\nPlease only decrypt files in " \
                       "groups which are encrypted by the same user."
DECRYPTING_FILES_MSG = "Decrypting files..."
NO_IDENETICAL_ID_TITLE = "Bulldog- Error"


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
    server_socket = connect_to_server(CONNECTING_TO_SERVER_TEXT)
    app = GUI.QtGui.QApplication(sys.argv)

    window = GUI.LoginWindow(server_socket)
    window.exec_()

    user_id = window.user_id

    if user_id == encrypter_id:
        login_data = window.correct_username + networking.DATA_SEP + window.correct_password
    elif user_id != -1:
        while user_id != -1 and user_id != encrypter_id:
            message = GUI.create_popup_message_box(text=WRONG_USER_TEXT, title=WRONG_USER_TITLE)
            message.exec_()
            window = GUI.LoginWindow(server_socket)
            window.exec_()
            user_id = window.user_id

        if user_id == -1:
            login_data = "-1" + networking.DATA_SEP + "-1"
        else:
            login_data = window.correct_username + networking.DATA_SEP + window.correct_password
    else:
        login_data = "-1" + networking.DATA_SEP + "-1"

    logout_msg = networking.BDTPMessage(operation=networking.OPERATIONS['logout'],
                                        status=networking.STATUS_CODES['request'], data='')
    server_socket.send(logout_msg.pack())
    server_socket.close()

    parent_input.send(login_data)
    parent_input.close()


def find_files_encrypter_id(paths):
    """
    This function will find the id of the user which encrypted the selected file/s.
    :param paths: A list of the file paths which should be decrypted.
    :type paths: list of str.
    :return: The id of the user which encrypted the given files. Note: If given an empty directory, the function will
    return 0. If there isn't one, identical id for all files the function will return -1.
    :rtype: int
    """
    if len(paths) == 0:
        return -1

    first_user_id, first_file_id = encryption.scan_file_header(paths[0])

    if len(paths) == 1:
        return first_user_id

    for path in paths[1:]:
        user_id, file_id = encryption.scan_file_header(path)
        if user_id != first_user_id:
            return -1

    return first_user_id


@GUI.blocking_operation
def decrypt_files(paths_to_decrypt, user_id, server):
    """

    :param paths_to_decrypt:
    :param user_id:
    :param server:
    :return:
    """
    for file_path in paths_to_decrypt:
        encrypter_id, file_id = encryption.scan_file_header(file_path)
        request_data = "%d%s%d" % (user_id, networking.DATA_SEP, file_id)
        decryption_request = networking.BDTPMessage(networking.OPERATIONS['decrypt file'],
                                                    status=networking.STATUS_CODES['request'], data=request_data)
        server.send(decryption_request.pack())
        response = server.smart_recv()
        file_info = networking.EncryptedFile.unpack(response.get_data())
        encryption.decrypt_file(file_path, file_info.method, file_info.iv, file_info.key)

        os.remove(file_path)


def main():
    """
    The main function of the program. Will decrypt the given files in the system arguments.
    :return: None
    """
    paths_to_decrypt = [path for path in get_directory_files_list(sys.argv[1]) if path.endswith(ENCRYPTED_FILES_ENDING)]

    encrypter_id = find_files_encrypter_id(paths_to_decrypt)
    if encrypter_id == -1:
        GUI.launch_popup_message_box(text=NO_IDENTICAL_ID_TEXT, title=NO_IDENETICAL_ID_TITLE)

    # Find the username of the user which encrypted the files
    username, password = start_login_subprocess(find_username_and_password, encrypter_id)
    if username == "-1":
        sys.exit(1)

    server = connect_to_server(CONNECTING_TO_SERVER_TEXT)

    user_id = perform_login(server, username, password)

    # Decrypt the selected files:
    decrypt_files(DECRYPTING_FILES_MSG, paths_to_decrypt, user_id, server)

    # Logout from the server:
    logout_msg = networking.BDTPMessage(operation=networking.OPERATIONS['logout'],
                                        status=networking.STATUS_CODES['request'], data='')
    server.send(logout_msg.pack())
    server.close()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        exit(-1)
