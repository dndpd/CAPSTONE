import socket
import threading
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# AES 암호화 및 복호화 함수
def encrypt_data(key, plaintext):
    iv = os.urandom(16)  # Initialization Vector (IV)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return iv + ciphertext  # IV를 함께 전송

def decrypt_data(key, ciphertext):
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    return plaintext.decode()

def threaded(client_socket, addr, key):
    print(f"Connected by: {addr[0]}:{addr[1]}")

    while True:
        try:
            data = client_socket.recv(1024)
            if not data:
                print(f"Disconnected by {addr[0]}:{addr[1]}")
                break

            # 데이터를 복호화
            decrypted_message = decrypt_data(key, data)
            print(f"Received from {addr[0]}:{addr[1]}: {decrypted_message}")

            # 응답 메시지를 암호화하여 전송
            response = "Server received your message."
            encrypted_response = encrypt_data(key, response)
            client_socket.send(encrypted_response)
        
        except ConnectionResetError as e:
            print(f"Disconnected by {addr[0]}:{addr[1]} due to error: {e}")
            break

# 서버 소켓 설정
ip = '127.0.0.1'
port = 8080

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind((ip, port))
server_socket.listen()

# 키 입력 (16바이트 AES 키)
key_input = input("Enter a 16-byte key for encryption: ")
key = key_input.encode()  # 문자열을 바이트로 변환

print("Server started and waiting for clients...")

while True:
    client_socket, addr = server_socket.accept()
    thread = threading.Thread(target=threaded, args=(client_socket, addr, key))
    thread.start()
