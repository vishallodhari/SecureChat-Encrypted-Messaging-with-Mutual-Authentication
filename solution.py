import socket
import base64
import contextlib
import json
import select
import random
import hashlib
import time
import getpass
import zlib
from datetime import datetime, timezone
from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from Crypto.Util.Padding import pad, unpad

# Note1 :  in some places there are deliberate time delays to allow the user to read it well
# Note2 : In some functions, creating inline variable and then returning it in next line is waste of variables so it is being avoided

"""
the encrption functions require the usage of bytes as input so there are 
many conversions in the program to match the type.
"""


class ChatApp:

    def __init__(self) -> None:

        # generate diffie hellman parameters with cryptography library
        self.parameters = dh.generate_parameters(
            generator=2, key_size=1024, backend=default_backend())
        # generation of dh parameters takes time
        # So init method helps to generate the parameters first and then carrying on with further code implementation

    """
    Diffie Hellman code is mostly with reference from cryptography.io documentation. 
    The sharing of keys by socket is crucial part of it.
    """

    def server_dhsk(self):

        # generate private key of receiver
        server_private_key = self.parameters.generate_private_key()
        server_public_key = server_private_key.public_key()

        # server public key is dhpublic key which cannot be sent directly via socket
        # serialising it and then pem key can be sent via socket
        server_pem_public = server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

        return server_pem_public, server_private_key

    def client_dhsk(self, server_pem_public):

        # the serialised pem key is sent to client

        dhpublickey = serialization.load_pem_public_key(
            server_pem_public, backend=default_backend())

        """
        client then generates parameters which will be same the parameters used by user
        """
        parameters = dhpublickey.parameters()
        client_private_key = parameters.generate_private_key()
        client_public_key = client_private_key.public_key()
        client_pem_public = client_public_key.public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

        # client sends pem public key to server for the generation of share key
        return client_pem_public, client_private_key

    def server_derived_key(self, server_private_key, client_public_key):

        # this function is used to generate shared key for the receiver

        client_public_key = serialization.load_pem_public_key(
            client_public_key, backend=default_backend())
        shared_key = server_private_key.exchange(client_public_key)
        """
        HKDF is a key derivation function (KDF) based on the HMAC message authentication code[1]
        """
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend(),
        ).derive(shared_key)

    def client_derived_key(self, client_private_key, server_public_key):

        # this function is used to generate shared key for the sender

        server_public_key = serialization.load_pem_public_key(
            server_public_key, backend=default_backend())
        shared_key = client_private_key.exchange(server_public_key)

        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend(),
        ).derive(shared_key)

    def chap_secret(self, dhsk, password):

        secret_string = password
        user_secret = bytes(secret_string, 'UTF-8')
        dhsk_str = str(dhsk)
        dhsk_byte = bytes(dhsk_str, 'UTF-8')

        # hmac function takes input in bytes so the input data is converted to bytes
        # hmac takes the derived key from dhsk and password as input with SHA256 as the hash mode

        hmac_obj = HMAC.new(dhsk_byte, user_secret, digestmod=SHA256)

        enc_key = hmac_obj.hexdigest()
        enc_key_bytes = bytes(enc_key, 'UTF-8')

        h = SHA256.new(enc_key_bytes)
        # iv has to be 16 bytes out of the total 32 so used slice function to get the first 16 bytes
        iv = h.hexdigest()[:16]

        iv_bytes = bytes(iv, 'UTF-8')
        iv_sha = SHA256.new(iv_bytes)

        hmac_key = iv_sha.hexdigest()
        hmac_bytes = bytes(hmac_key, 'UTF-8')

        chap = SHA256.new(hmac_bytes)

        chap_secret = chap.hexdigest()
        # chap_secret will be used for mutual chap of the both the parties

        return chap_secret, iv_bytes, hmac_key

    def open_dictionary(self, dir):

        with open(dir, "r") as f:
            # used to open a file name which is mentioned by the user
            user_dict = json.load(f)

        return user_dict

    def encryption(self, text, dhsk, iv):
        """
        Encryption and decryption referred from pycryptodome documentation.
        It has pad and unpad function which is more efficient to use than using pkcs7 padder from cryptography.
        Pad and unpad has default pkcs7 padder in them unless changed differently
        """
        # this should be dhsk key of 32 bytes
        cipher = AES.new(dhsk, AES.MODE_CBC, iv)
        text = bytes(text, 'utf-8')

        ct_bytes = cipher.encrypt(pad(text, AES.block_size))

        return (b64encode(ct_bytes).decode('utf-8'))

    def decryption(self, body, dhsk, iv):

        # the encrypted message is base64 encoded so it needs to be b64decoded first

        body = b64decode(body)
        cipher = AES.new(dhsk, AES.MODE_CBC, iv)

        return (unpad(cipher.decrypt(body), AES.block_size))

    def sender_mutual_chap(self, send_socket, password):

        # Sending a hello message to the receiver so that the authentication can be started
        send_socket.send("hello:None".encode())
        print("\n*************************************************")
        print("Sent hello message")
        print("*************************************************")

        # receiving public key from the server and then giving it to the client dhsk function
        server_public_key = send_socket.recv(1024)
        client_pem_public, client_private_key = self.client_dhsk(
            server_public_key)

        send_socket.send(client_pem_public)

        # this is the derived key for the sender
        dhsk = self.client_derived_key(client_private_key, server_public_key)

        # Wait for challenge message
        start_time = time.time()
        while True:
            challenge_message = send_socket.recv(1024)
            if challenge_message:
                print("\n*************************************************")
                print("Received challenge message")
                print("*************************************************")
                break
            if time.time() - start_time > 10:
                print("No challenge message received. Closing socket.")
                send_socket.close()
                break

        # Extract challenge value from message
        challenge_value = challenge_message.decode().split(":")[1]

        # Compute SHA256 of challenge value concatenated with password
        sha256 = hashlib.sha256()
        sha256.update((challenge_value + password).encode())
        response = sha256.hexdigest()

        # Send response message
        send_socket.send(f"response:{response}".encode())
        print("\n*************************************************")
        print("Sent response message")
        print("*************************************************")

        # Wait for ack or nack message
        start_time = time.time()
        while True:
            if ack_nack_message := send_socket.recv(1024):
                message_type, message_body = ack_nack_message.decode().split(":")
                if message_type == "ack":
                    print("\n*************************************************")
                    print("Authentication successful")
                    print("*************************************************")

                    break
                elif message_type == "nack":
                    print("Authentication failed:", message_body)
                    send_socket.close()
                    break
            if time.time() - start_time > 10:
                print("No ack or nack message received. Closing socket.")
                send_socket.close()
                break

        # this is the start of server authentication
        # secretkey = self.dhsk()
        chapsecret, iv, hmac_val = self.chap_secret(dhsk, password)

        auth_response_message = send_socket.recv(1024)
        auth_response_body = auth_response_message.decode().split(":")[1]

        """ 
        sha256 hashed challenge+chapsecret is received by the client which will then be validated 
        """
        sha256 = hashlib.sha256()
        sha256.update((challenge_value + chapsecret).encode())
        auth_expected_response = sha256.hexdigest()

        # Check if the received value is the same as the internal computed value
        if auth_response_body != auth_expected_response:

            send_socket.send("nack:Invalid response".encode())
            print("Sent nack message for server")
        else:

            send_socket.send("ack:Authentication successful".encode())
            print("\n*************************************************")
            print("Sent ack message for server")
            print("*************************************************")
        return dhsk, iv, hmac_val

    def receiver_mutual_chap(self, conn, addr, password):
        while True:
            hello_message = conn.recv(1024)
            # Check if the body of the message is None
            if hello_message.decode().split(":")[1] != "None":
                # Send nack message
                conn.send("nack:Invalid message format".encode())
                conn.close()
                continue
            else:
                print("\n*************************************************")
                print("Received hello message")
                print("*************************************************")
                # server dhsk
                server_pem_public, server_private_key = self.server_dhsk()

                conn.send(server_pem_public)

            client_public_key = conn.recv(1024)
            """if clientpublickey.split(":")[1] != None:
                client_public_key =  clientpublickey.split(":")[1]
            """
            dhsk = self.server_derived_key(
                server_private_key, client_public_key)

            # Send challenge message
            challenge_value = str(random.getrandbits(256))
            conn.send(f"challenge:{challenge_value}".encode())
            print("\n*************************************************")
            print("Sent challenge value")
            print("*************************************************")

            # Receive response message
            response_message = conn.recv(1024)
            response_body = response_message.decode().split(":")[1]

            # Compute SHA256 of challenge value concatenated with password
            sha256 = hashlib.sha256()
            sha256.update((challenge_value + password).encode())
            expected_response = sha256.hexdigest()

            # Check if the received value is the same as the internal computed value
            if response_body != expected_response:
                # Send nack message
                conn.send("nack:Invalid response".encode())
                print("Sent nack message")
            else:
                # Send ack message
                conn.send("ack:Authentication successful".encode())
                print("\n*************************************************")
                print("Sent ack message")
                print("\n*************************************************")

            # mutual chap

            # self.secretkey = self.dhsk()
            chapsecret, iv, hmac_key = self.chap_secret(dhsk, password)

            sha256 = hashlib.sha256()
            sha256.update((challenge_value + chapsecret).encode())
            server_auth = sha256.hexdigest()

            conn.send(f"Auth:{server_auth}".encode())
            print("\n*************************************************")
            print("Sent receiver authentication message")
            print("*************************************************")

            # Wait for ack or nack message
            start_time = time.time()
            while True:
                if ack_nack_message := conn.recv(1024):
                    message_type, message_body = ack_nack_message.decode().split(":")
                    if message_type == "ack":
                        print("\n*************************************************")
                        print("Receiver Authentication successfu")
                        print("*************************************************")

                        break
                    elif message_type == "nack":
                        print("Server Authentication failed:", message_body)
                        conn.close()
                        break
                if time.time() - start_time > 10:
                    print("No ack or nack message received. Closing socket.")
                    conn.close()
                    break
            return dhsk, iv

    def crc_generate(self, message):
        """
        zlib.crc32 function gives a 32 bit unsigned integer which is then given 
        to server for validation
        """

        msg = json.dumps(message)
        bmsg = bytes(msg, 'utf-8')
        crc = zlib.crc32(bmsg)
        message['header']['crc'] = crc

        return message

    def crc_check(self, message):
        """
        Computes a CRC (Cyclic Redundancy Check) checksum of data.
        this can help in checking if the message is tampered
        """
        crc = message['header']['crc']
        message['header']['crc'] = None
        msg = json.dumps(message)
        bmsg = bytes(msg, 'utf-8')
        response_crc = zlib.crc32(bmsg)
        if response_crc != crc:
            print('Mismatched crc, message is tampered')
        else:
            print("\n*************************************************")
            print('CRC is checked and it is valid')
            print("*************************************************")
        return

    def securelogging(self, message, password):
        with open('logging.txt', 'a') as f:
            """
            logging the message received
            """
            timestamp = datetime.now(
                timezone.utc).strftime("%d-%m-%Y %H:%M:%S")
            log_entry = f'{timestamp} + {message}'
            password = bytes(password, 'utf-8')
            log_bytes = bytes(log_entry, 'utf-8')

            hmac_obj = HMAC.new(password, log_bytes, digestmod=SHA256)
            hmac_value = hmac_obj.hexdigest()
            new_entry = f'{log_entry}::HMAC:{hmac_value}\n'
            f.write(new_entry)
        f.close()

    def clientlogging(self, message, password):
        with open('clientlogging.txt', 'a') as f:
            """
            logging the message which is sent by user
            """
            timestamp = datetime.now(
                timezone.utc).strftime("%d-%m-%Y %H:%M:%S")
            log_entry = f'{timestamp} + {message}'
            password = bytes(password, 'utf-8')
            log_bytes = bytes(log_entry, 'utf-8')

            hmac_obj = HMAC.new(password, log_bytes, digestmod=SHA256)
            hmac_value = hmac_obj.hexdigest()
            new_entry = f'{log_entry}::HMAC:{hmac_value}\n'
            f.write(new_entry)
        f.close()

    def receive_with_timeout(self, conn, addr, timeout, password, dhsk, iv):
        ready = select.select([conn], [], [], timeout)
        if ready[0]:
            data = conn.recv(1024).decode()
            if len(data) != 0:
                with contextlib.suppress(json.decoder.JSONDecodeError):
                    pdu = json.loads(data)
                    header = pdu['header']
                    if header['msg_type'] == 'text':
                        self.crc_check(pdu)
                        body = pdu['body']
                        text = self.decryption(body, dhsk, iv).decode('utf-8')
                        print("\n*************************************************")
                        print("Received Message: ", text)
                        print("*************************************************")
                        self.securelogging(text, password)

                        ack_header = {'msg_type': 'ack'}
                        ack_pdu = {'header': ack_header, 'body': None}
                        ack_json_data = json.dumps(ack_pdu)
                        conn.sendall(ack_json_data.encode())
                    elif header['msg_type'] == 'close':
                        print("Closing connection from", addr)
                        conn.close()
                        return None
            return data
        return None

    def receive_msg(self, dict, port):

        password = next((u['password'] for u in dict if u['port'] == port), '')
        if password == '':
            print('Incorrect port, try again...')
            self.receive_msg(dict, port)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('', port))
        s.listen(1)

        print("\n*************************************************")
        print("Server listening on ", port, "port")
        print("*************************************************\n")
        timeout = 25.0
        while True:
            conn, addr = s.accept()

            print("\n*************************************************")
            print("Connected from ", addr)
            print("*************************************************")
            dhsk, iv = self.receiver_mutual_chap(conn, addr, password)

            data = self.receive_with_timeout(
                conn, addr, timeout, password, dhsk, iv)

    def send_msg(self, dict):
        ip = ''
        user = ''
        msg_type = 'text'
        timestamp = time.time()

        # security
        hmac_type = 'SHA256'

        print("\n*************************************************")
        mode = input("Do you know the username: Y/N \t")

        print("*************************************************\n")

        if mode.upper() == 'Y':
            print("*************************************************")
            user = input("Enter Username: ")
            print("*************************************************")
        elif mode.upper() == 'N':
            ip = input("Enter IP: ")
            port = int(input("Enter port: "))

        print("\n*************************************************")
        password = getpass.getpass()
        print("*************************************************")

        for u in dict:
            if u['username'] == user and u['password'] == password:
                ip = u['ip']
                port = u['port']
                break
            elif u['ip'] == ip and u['port'] == port:
                break

        if ip == '':
            print('incorrect username or password, try again...')
            self.send_msg(dict)

        print("\n*************************************************")
        text = input("Enter text message: ")
        print("*************************************************")
        # header

        send_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        send_socket.connect((ip, port))

        dhsk, iv, hmac_val = self.sender_mutual_chap(send_socket, password)

        header = {'msg_type': msg_type, 'crc': None, 'timestamp': timestamp}
        body = self.encryption(text, dhsk, iv)
        security = {'hmac': {'hmac_type': hmac_type,
                             'hmac_val': hmac_val}, 'enc_type': 'AES256CBC'}

        # this is the message format
        message = {'header': header, 'body': body, 'security': security}

        message_with_crc = self.crc_generate(message)
        json_data = json.dumps(message_with_crc)

        attempts = 0
        while attempts < 3:
            send_socket.sendall(bytes(json_data, 'utf-8'))

            print("\n*************************************************")
            print("Sent message:", text)
            print("*************************************************")
            try:
                ack_data = send_socket.recv(1024).decode()
                ack_pdu = json.loads(ack_data)
                ack_header = ack_pdu['header']
                if ack_header['msg_type'] == 'ack':
                    print("\n*************************************************")
                    print("Message successfully sent")
                    print("*************************************************")
                    self.clientlogging(text, password)
                    break
            except socket.timeout:
                attempts += 1
                print("Timeout, retrying...")
        print("\n*************************************************")
        print("Closing the application now")
        print("*************************************************")
        send_socket.close()
        if attempts == 3:
            print("Failed to receive ACK from server after 3 attempts, closing socket")


def loading_simple_ui():
    print("*************************************************")
    print("**********Loading your chat application**********")
    print("*************************************************")

    obj = ChatApp()

    print("\n*************************************************")
    print("+++++++++++++++Loading complete++++++++++++++++++")
    print("*************************************************\n")
    time.sleep(0.25)
    print("*************************************************")
    print("********** Welcome to the Chat App **************")
    time.sleep(0.25)
    print("*************************************************")
    time.sleep(0.25)
    return obj


def main():
    obj = loading_simple_ui()
    print("\n*************************************************")
    user_dir = input("Enter the directory: \t")
    print("*************************************************")
    time.sleep(0.25)
    user_dict = obj.open_dictionary(user_dir)

    print("\n*************************************************")
    port = int(input("Enter port number: \t"))
    print("*************************************************")
    time.sleep(0.25)

    print("\n*************************************************")
    mode = input("Enter r or s to receive or send a message ").lower()
    print("*************************************************")
    time.sleep(0.25)

    if mode == 'r':
        obj.receive_msg(user_dict, port)
    elif mode == 's':
        obj.send_msg(user_dict)
    else:
        print("incorrect input")


if __name__ == "__main__":
    main()


"""
References:

[1] Krawczyk. (n.d.). Cryptographic Extraction and Key Derivation: The HKDF Scheme. Advances in Cryptology – CRYPTO 2010, 631–648. https://doi.org/10.1007/978-3-642-14623-7_34

"""
