# SecureChat-Encrypted-Messaging-with-Mutual-Authentication

**SecureChat** is a Python-based encrypted messaging application designed to ensure secure communication between two parties over a network. It leverages advanced cryptographic techniques such as Diffie-Hellman key exchange, AES encryption, HMAC authentication, and CRC32 message integrity checks to ensure both confidentiality and integrity during message transmission. The project offers a simple chat interface where users can send and receive encrypted messages with mutual authentication.

## Features

- **Diffie-Hellman Key Exchange:** Securely generates shared keys between the sender and receiver without transmitting the private keys over the network.
- **AES Encryption (CBC mode):** Utilizes AES encryption in Cipher Block Chaining (CBC) mode for message encryption, ensuring data confidentiality.
- **HMAC Authentication:** Both the sender and receiver authenticate each other using HMAC (Hash-based Message Authentication Code) and SHA256 hashing to ensure mutual trust.
- **CRC32 Message Integrity Check:** Each message includes a CRC32 checksum to ensure that no tampering or data corruption has occurred during transmission.
- **Session Logging with HMAC:** All messages sent and received are logged with an HMAC value, ensuring the integrity of the log files.
- **Mutual Challenge-Response Authentication:** Employs a challenge-response mechanism for mutual authentication between the sender and receiver.
- **Simple User Interface:** A basic command-line interface for entering usernames, IP addresses, and port numbers, making the application user-friendly.

## How it Works

### 1. Diffie-Hellman Key Exchange
SecureChat implements the Diffie-Hellman (DH) protocol to generate a shared secret key between the client and server. The key is generated through a secure exchange of public keys. This key is then used for message encryption with AES.

### 2. AES Encryption with CBC Mode
The shared DH key is used for encrypting and decrypting the messages using AES in CBC mode, which provides confidentiality by ensuring that each message is encrypted with a unique initialization vector (IV).

### 3. Mutual Authentication with HMAC and SHA256
The application uses HMAC (Hash-based Message Authentication Code) to verify the integrity and authenticity of messages between the sender and receiver. Both parties authenticate each other using a challenge-response mechanism, which ensures that only authorized users can communicate.

### 4. Message Integrity with CRC32
SecureChat uses a CRC32 checksum to detect any tampering or corruption of messages during transmission. Each message is assigned a CRC value, which is checked upon receipt to ensure the message has not been altered.

### 5. Session Logging
SecureChat keeps track of all sent and received messages in log files (both on the client and server). Each log entry is appended with an HMAC value, ensuring the log cannot be tampered with without detection.

## Usage

### 1. Setting Up

### Step 1: Create a JSON File with User Information

The application expects a JSON file containing user details such as `username`, `password`, `IP`, and `port`. An example format is shown below:

```json
[
    {
        "username": "user1",
        "password": "password1",
        "ip": "127.0.0.1",
        "port": 12345
    },
    {
        "username": "user2",
        "password": "password2",
        "ip": "127.0.0.1",
        "port": 12346
    }
]
```

###Step 2: Start the Application
Run the following command to start the application:

```json
python secure_chat.py
```
### Step 3: Input Prompt
You will be prompted to enter the path to the JSON file.
Then, select whether you want to send or receive a message:
- **To send a message, input the recipient's username or IP and port.
- **To receive a message, ensure the correct port is used for your user.
2. Authentication Flow

The sender initiates the connection with a "hello" message.
The server responds by sending a Diffie-Hellman (DH) public key.
After deriving the shared key, the server sends a challenge message.
The client computes a response using a SHA256 hash of the challenge and the password, which the server verifies.
Mutual authentication is completed when the client verifies the server's response to its challenge.
3. Encryption and Decryption

Once authentication is successful, message transmission begins.
All messages are encrypted using AES with a derived key from the DH key exchange.
Messages are padded to align with block size requirements.
4. Message Logging

Each sent or received message is logged along with an HMAC for integrity verification.
Logs:
Server logs are saved in logging.txt.
Client logs are saved in clientlogging.txt.
Example Scenario
The sender inputs the recipient's username or IP address.
The server listens for incoming connections on the specified port.
Both parties authenticate using Diffie-Hellman and mutual HMAC validation.
Messages are encrypted and securely transmitted.
Each message, along with its HMAC, is logged for data integrity verification.
5. Security Considerations

Key Exchange
The Diffie-Hellman key exchange ensures the shared encryption key is never transmitted over the network, minimizing the risk of interception.

Message Integrity
CRC32 and HMAC are used to ensure message integrity and to verify that logs remain untampered.

Mutual Authentication
The challenge-response mechanism ensures that only authorized users can communicate, providing protection against replay and man-in-the-middle attacks.

6. Dependencies

The following Python libraries are required:

pycryptodome: Provides AES encryption and HMAC for message authentication.
cryptography: Used for Diffie-Hellman key exchange and other cryptographic utilities.
socket: Python's built-in library for networking.
json: Built-in library for working with JSON data.
zlib: Built-in library for generating CRC32 checksums.
Install dependencies
Run the following command to install the required dependencies:

bash
Copy code
pip install pycryptodome cryptography
7. Future Enhancements

GUI Implementation: Develop a graphical user interface to replace the command-line interface.
Additional Encryption Modes: Support for more encryption protocols such as GCM for authenticated encryption.
Group Messaging: Allow multiple users to participate in the same chat session with end-to-end encryption.
8. References

Krawczyk, H. (2010). Cryptographic Extraction and Key Derivation: The HKDF Scheme. Advances in Cryptology – CRYPTO 2010, 631–648. https://doi.org/10.1007/978-3-642-14623-7_34
PyCryptodome Documentation
Cryptography.io Documentation



- Make sure you have the following libraries installed:
  ```bash
  pip install pycryptodome cryptography
