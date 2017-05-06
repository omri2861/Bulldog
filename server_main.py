import socket
from Bulldog import networking
import time
import select
import threading
from time import sleep
from pickle import loads
import subprocess

"""
This program is the main server program. It will communicate with the client and link it with the database.
"""

MAX_CLIENTS = 20
SEPERATOR = '\r\n'
ID_ANSWER_FORMAT = "i"
USER_INACTIVITY_TIMEOUT = 120
SOCKET_TIMEOUT_WARNING = "The socket connected by the user %s is inactive, therefore kicked out of the server."
SOCKET_ERROR_WARNING = "The socket connected by the user %s had an error, therefore kicked out of the server."
SELECT_TIMEOUT = 0.7
ROUND_TIME = 1
DATABASE_PORT = 7091
COMMIT = "commit"
DATABASE_PATH = r"F:\Cyber\Bulldog\database\attempt2.db"
IP = "0.0.0.0"
PORT = 8080
ADDRESS = IP, PORT


class ActiveClient(object):
    """
This class will represent an active client. It will allow the server to remember the currently logged in and active
users.

    properties:
    socket: The socket which the user is currently connected to.
    id: int. The id of the current user.
    last_activity: float. When did the user log in (the return value of time.clock() when the user is logged in.).
    username: str. The active user's username.
    """
    def __init__(self, user_socket, user_id, username):
        """
    Receives the user's attributes and creates an ActiveClient class instance.
        :param user_socket:
        :param user_id: int. The connected user's id as an integer.
        :param username:
        """
        self.socket = user_socket
        self.id = user_id
        self.last_activity = time.clock()
        self.username = username

    def __eq__(self, other):
        """
    The function will be called upon the usage of '=='. It can receive various types of objects as 'other', so the
    active user can be easily found in a list when only it's socket or id know to the program.

        :param other: ActiveClient or socket.socket or str or int.
        :return: Boolean. True if self == other, False otherwise.
        """
        if isinstance(other, type(self)):
            return self.socket == other.socket and self.id == other.id
        elif isinstance(other, networking.BulldogSocket):
            return self.socket == other
        elif isinstance(other, str):
            return other == str(self.id)
        elif isinstance(other, int):
            return self.id == other
        else:
            return False

    def activated(self):
        """
    This function should be ran whenever the user performs an operation of any type. This function will set the time
    of last activity, so the user will still be considered an active user and will not be ignored by the server.

        :return: None
        """
        self.last_activity = time.clock()

    def __str__(self):
        """
        :return: str. A description meant for printing. The string which will be returned is not memory- efficient and
        should not be sent throughout a socket or interpreted by regex. It is only for logging and debugging.
        """
        description = "The user is '%s'. \n" % self.username
        description += "It's id is %d. \n" % self.id
        description += "It's connected through the socket at: %s. \n" + str(socket)
        return description


def authenticate_user(username, password, database):
    """
    This function will check if the username and password are found in the database. If so,
    it will return the user id as an int. If not, it will return -1.
    :param username: str. The username of the signing in user.
    :param password: str. The password of the signing in user.
    :param database: The loopback socket which is connected to the database operator program.
    :return: int. The id of the logged in user.
    """
    COMMAND = "SELECT user_id FROM users WHERE username = '%s' and user_password = '%s';"
    database.send(COMMAND % (username, password))

    response = database.recv(networking.BAND_WIDTH)  # No need to take care of any responses larger than the bandwidth,
    # as such a large response from the database will not be sent.
    response = loads(response)
    if len(response) == 0:  # Meaning an empty list
        return -1
    else:
        user_id = response[0][0]  # First place in the first tuple of the list

        database.send(COMMIT)
        response = database.recv(networking.BAND_WIDTH)  # Doesn't really matter if the commit was successfull or not.
        # If it wasn't successfull, the database must have an error, which will be excepted and handled by the next
        # request.

        return user_id


def perform_login(request, client_sock, logged_in_users, database):
    """
This function will handle a login message and will return the response which should be sent to the client.

    :param request: BDTPMessage. The message sent from the client, interpreted and implanted in a BDTPMessage class.
    :param client_sock: socket.socket. The sending client's socket.
    :param logged_in_users: list. The list of the currently active users.
    :param database: The loopback socket which is connected to the database operator program.
    :return: BTDPMessage. The response to the login request.
    """
    login_answer = networking.BDTPMessage(operation=networking.OPERATIONS['login'],
                                          status=networking.STATUS_CODES['OK'], data='')
    username, password = tuple(request.get_data().split(SEPERATOR))
    user_id = authenticate_user(username, password, database)
    login_answer.set_data(user_id)
    # TODO: Create Error Codes
    if user_id != -1:
        logged_in_users.append(ActiveClient(client_sock, user_id, username))
    return login_answer


def add_file_to_database(new_file, user_id, database):
    """
This function will receive a file which should be added to the database, encrypted by the user which it's id is
given.

    :param new_file: networking.EncryptedFile. The data of the file which the client requests to encrypt, represented
    by a networking.EncryptedFile object.
    :param user_id: int. The id of the user which requests to encrypt the file.
    :param database: The loopback socket which is connected to the database operator program.
    :return: int. If the file was successfully added to the database, it's new id will be returned. If an error
    occurred, -1 will be returned.
    """
    values = (user_id, new_file.method, new_file.iv, new_file.key.encode('base64'))
    COMMAND = "INSERT INTO files (user_id, method, iv, key) VALUES (%d, %d, '%s', '%s');"
    CONFIRMING_COMMAND = "SELECT file_id FROM files WHERE user_id = %d and method = %d and iv = '%s' and key = '%s';"
    database.send(COMMAND % values)

    result = database.recv(networking.BAND_WIDTH)  # No need to take care of any responses larger than the bandwidth,
    # as such a large response from the database will not be sent.
    result = loads(result)

    if result:
        database.send(CONFIRMING_COMMAND % values)
        result = database.recv(networking.BAND_WIDTH)
        result = loads(result)
        file_id = result[0][0]
        database.send(COMMIT)
        result = database.recv(networking.BAND_WIDTH)  # Doesn't really matter if the commit was successfull or not.
        # If it wasn't successfull, the database must have an error, which will be excepted and handled by the next
        # request.
    else:
        file_id = -1

    return file_id


def add_encrypted_file(request, user_id, database):
    """
This function will take care of a request to encrypt a new file from a client.

    :param request: BDTPMessage object. The request sent from the client.
    :param user_id: The id of the user which requests to encrypt the file.
    :param database: The loopback socket which is connected to the database operator program.
    :rtype: networking.BDTPMessage
    :return: The response which should be sent to the client.
    """
    encrypted_file = networking.EncryptedFile.unpack(request.get_data())
    new_file_id = add_file_to_database(encrypted_file, user_id, database)
    return networking.BDTPMessage(operation=networking.OPERATIONS['add file'], status=0,
                                  data=new_file_id)


def get_file_info_from_database(file_id, user_id, database):
    """

    :param file_id:
    :param user_id:
    :param database: The loopback socket which is connected to the database operator program.
    :return:
    """
    COMMAND = "SELECT method, iv, key FROM files WHERE user_id = %d and file_id = %d;"
    database.send(COMMAND % (user_id, file_id))

    result = database.recv(networking.BAND_WIDTH)  # Doesn't really matter if the commit was successfull or not.
    # If it wasn't successfull, the database must have an error, which will be excepted and handled by the next request.
    result = loads(result)
    method, iv, key = result[0]
    key = str(key)  # decode it from unicode to ascii string
    iv = str(iv)  # same for the iv
    key = key.decode('base64')  # Then from base64. This one is only necessary for the key

    return networking.EncryptedFile(method, iv, key)


def extract_file_info(request, user, database):
    """
    This function will create a response for a user which requests to decrypt a file. It will give the user the required
    information to so, if the user gained permission.
    :param request: networking.BDTPMessage object. The request which was received from the user.
    :param user: The ActiveClient object which matches the socket, to check that the requesting user has the permission
    to perform the operation.
    :param database: The loopback socket which is connected to the database operator program.
    :return: networking.BDTPMessage object. The response for the user.
    """
    requester_id, file_id = tuple(request.get_data().split(networking.DATA_SEP))
    requester_id = int(requester_id)
    file_id = int(file_id)
    if requester_id != user.id:
        response = networking.BDTPMessage(networking.OPERATIONS['decrypt file'],
                                          networking.STATUS_CODES['unauthorized'], data="")
    else:
        file_info = get_file_info_from_database(file_id, user.id, database)
        response = networking.BDTPMessage(networking.OPERATIONS['decrypt file'], networking.STATUS_CODES['OK'],
                                          data=file_info.pack())

    return response


def receive_and_handle_message(client_sock, logged_in_users, database):
    """
This function will receive the message from the readable socket given, will handle the request and finally send a
response to the request.
This function is built to be working as a thread in a multiclient server.

    :param client_sock: socket.socket object. The readable socket which contains the request.
    :param logged_in_users: list. The list of logged in users, each item in the list should be an ActiveClient instance
    which contains the logged in user's data.
    :param database: The loopback socket which is connected to the database operator program.
    :return: True if the session should continue, false otherwise.
    """
    request = client_sock.smart_recv()
    print request

    if request is None:
        return False

    if request.operation == networking.OPERATIONS['login']:
        response = perform_login(request, client_sock, logged_in_users, database)
    elif request.operation == networking.OPERATIONS['add file']:
        requesting_user = logged_in_users[logged_in_users.index(client_sock)]
        response = add_encrypted_file(request, requesting_user.id, database)
    elif request.operation == networking.OPERATIONS['decrypt file']:
        requesting_user = logged_in_users[logged_in_users.index(client_sock)]
        response = extract_file_info(request, requesting_user, database)
    elif request.operation == networking.OPERATIONS['logout']:
        client_sock.close()
        logged_in_users.remove(client_sock)
        return False
    else:
        response = networking.BDTPMessage(operation=networking.OPERATIONS['kickout'],
                                          status=networking.STATUS_CODES['bad protocol usage'], data="")
        client_sock.send(response.pack())
        client_sock.close()
        return False

    client_sock.send(response.pack())
    return True


def start_session(client, logged_in_users, database):
    """
    This function will handle a session with a single connected client. The function will take care of all of the
    client's requests, and will then end the communication with him. This function should run as a thread for each
    connected client.
    :param client: The client's socket.
    :param logged_in_users: The list of active users class of the server.
    :param database: The socket connected to the database.
    :return: None
    """
    continue_session = True
    while continue_session:
        try:
            continue_session = receive_and_handle_message(client, logged_in_users, database)
        except socket.timeout:
            logout_msg = networking.BDTPMessage(operation=networking.OPERATIONS['kickout'],
                                                status=networking.STATUS_CODES['inactivity logout'], data='')
            client.send(logout_msg.pack())
            client.close()

            try:
                active_client = logged_in_users[logged_in_users.index(client)]
                username = active_client.username
            except ValueError or IndexError:
                username = "unknown"

            print SOCKET_TIMEOUT_WARNING % username
            continue_session = False

        except socket.error:
            client.close()

            try:
                active_client = logged_in_users[logged_in_users.index(client)]
                username = active_client.username
            except ValueError or IndexError:
                username = "unknown"

            print SOCKET_ERROR_WARNING % username
            continue_session = False


def main():
    """
    The main function of the program. Will run endlessly, constantly receiving requests and opening threads which handles
    them.
    :return: None
    """
    server_socket = networking.BulldogSocket()
    server_socket.bind(ADDRESS)
    server_socket.listen(MAX_CLIENTS)
    logged_in_users = []
    sessions = []

    database_process = subprocess.Popen("python database_operator.py %s" % DATABASE_PATH)
    sleep(2)
    database = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    database.connect(('loopback', DATABASE_PORT))

    running = True
    while running:
        readable, writable, excepted = select.select([server_socket], [], [])
        if readable:
            new_client, new_addr = server_socket.accept()
            new_session = threading.Thread(target=start_session, args=(new_client, logged_in_users, database))
            sessions.append(new_session)
            new_session.start()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print "Ended due to keyboard interrupt"
