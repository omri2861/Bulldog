import socket
from Bulldog import networking
import time
import struct

"""
This program is the main server program. It will communicate with the client and link it with the database.
"""

MAX_CLIENTS = 1
BAND_WIDTH = 1024
SEPERATOR = '\r\n'
ID_ANSWER_FORMAT = "i"
USER_INACTIVITY_TIMEOUT = 120


class ActiveClient(object):
    """
    This class will represent an active client. It will allow the server to remember the currently logged in and active
    users.
    properties:
    socket: The socket which the user is currently connected to.
    id: int. The id of the current user.
    last_activity: int. When did the user log in (the return value of time.clock() when the user is logged in.).
    username: str. The active user's username.
    """
    def __init__(self, user_socket, user_id, username):
        self.socket = user_socket
        self.id = user_id
        self.last_activity = time.clock()
        self.username = username

    def __eq__(self, other):
        if isinstance(other, type(self)):
            return self.socket == other.socket and self.id == other.id
        elif isinstance(other, socket.socket):
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


def authenticate_user(username, password):
    """
    This function will check if the username and password are found in the database. If so,
    it will return the user id as an int. If not, it will return -1.
    :param username: str. The username of the signing in user.
    :param password: str. The password of the signing in user.
    :return: int. The id of the logged in user.
    """
    # TODO: This function is one of the function which should be updated once the database is ready.
    if username == 'omri2861' and password == 'omripess':
        return 2861
    else:
        return -1


def perform_login(request, client_sock, logged_in_users):
    """
    This function will handle a login message and will return the response which should be sent to the client.
    :param request: BDTPMessage. The message sent from the client, interpreted and implanted in a BDTPMessage class.
    :param client_sock: socket.socket. The sending client's socket.
    :param logged_in_users: list. The list of the currently active users.
    :return: BTDPMessage. The response to the login request.
    """
    login_answer = networking.BDTPMessage(operation=networking.OPERATIONS['login'],
                                          flags=0, status=0, data='')
    username, password = tuple(request.data.split(SEPERATOR))
    user_id = authenticate_user(username, password)
    login_answer.data = struct.pack(ID_ANSWER_FORMAT, user_id)
    # TODO: Create Error Codes
    if user_id != -1:
        logged_in_users.append(ActiveClient(client_sock, user_id, username))
    return login_answer


def add_file_to_database(new_file):
    """

    :param new_file:
    :return: int. The file id.
    """
    # TODO: Connect this function with the database
    print "The file which should be saved to the database:"
    print new_file
    return 4321


def add_encrypted_file(request):
    """
    This function will take care of a request to encrypt a new file from a client.
    :param request: BDTPMessage object. The request sent from the client.
    :rtype: networking.BDTPMessage
    :return: The response which should be sent to the client.
    """
    encrypted_file = networking.EncryptedFile.unpack(request.data)
    new_file_id = add_file_to_database(encrypted_file)
    # TODO: Change status and flags if operation wasn't successfull
    return networking.BDTPMessage(operation=request.operation, flags=0, status=0,
                                  data=struct.pack(ID_ANSWER_FORMAT, new_file_id))


def receive_and_handle_message(client_sock, logged_in_users, active_sockets):
    """

    :param client_sock:
    :param logged_in_users:
    :param active_sockets: A list of the currently active sockets in the server.
    :return:
    """
    print "As the server, I just received:"
    msg = client_sock.recv(BAND_WIDTH)
    print msg

    # TODO: Handle message longer than the bandwidth
    print "Which means: "
    request = networking.BDTPMessage.unpack(msg)
    print str(request)

    if request.operation == networking.OPERATIONS['login']:
        response = perform_login(request, client_sock, logged_in_users)
        print logged_in_users
        print active_sockets
    elif request.operation == networking.OPERATIONS['add file']:
        response = add_encrypted_file(request)
    elif request.operation == networking.OPERATIONS['logout']:
        print logged_in_users
        print active_sockets
        client_sock.close()
        logged_in_users.remove(client_sock)
        active_sockets.remove(client_sock)
        # TODO: Remove this exit later:
        print "User logged out"
        exit()
        return
    else:
        # TODO: send error message and cut the connection, since the client does not use the latest version of BDTP.
        print "Unknown operation reached"
        response = None
        client_sock.send(response)
        client_sock.close()
        logged_in_users.remove(client_sock)
        active_sockets.remove(client_sock)
        return

    client_sock.send(response.pack())


def main():
    """
    The main function of the program.
    """
    logged_in_users = []
    active_sockets = []
    time.clock()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 8080))
    server_socket.listen(MAX_CLIENTS)
    client_sock, client_ip = server_socket.accept()
    active_sockets.append(client_sock)

    while True:
        receive_and_handle_message(client_sock, logged_in_users, active_sockets)

if __name__ == '__main__':
    main()
