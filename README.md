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

- Make sure you have the following libraries installed:
  ```bash
  pip install pycryptodome cryptography
