import socket
import threading
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# AES 암호화 함수
def encrypt_data(key, plaintext):
    iv = os.urandom(16)  # 16바이트 IV (초기화 벡터) 생성
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return iv + ciphertext  # IV를 함께 전송해야 복호화할 때 사용할 수 있음

# AES 복호화 함수
def decrypt_data(key, ciphertext):
    iv = ciphertext[:16]  # 처음 16바이트는 IV
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    return plaintext.decode()

# 클라이언트와 통신하는 스레드 함수
def threaded(client_socket, addr, key):
    print(f'Connected by: {addr[0]}:{addr[1]}')

    while True:
        try:
            # 클라이언트로부터 암호화된 데이터를 수신
            data = client_socket.recv(1024)
            if not data:
                print(f'Disconnected by {addr[0]}:{addr[1]}')
                break

            # 받은 데이터를 복호화
            try:
                decrypted_message = decrypt_data(key, data)
                print(f"Decrypted message from {addr[0]}:{addr[1]}: {decrypted_message}")
                
                # 응답도 암호화해서 전송
                response = "Message received successfully.".encode()
                encrypted_response = encrypt_data(key, response.decode())
                client_socket.send(encrypted_response)

            except Exception as e:
                print(f"Decryption failed: {e}")
                break

        except ConnectionResetError as e:
            print(f"Disconnected by {addr[0]}:{addr[1]}")
            print(f"Error: {e}")
            break

# 서버 소켓 설정
ip = '192.168.4.1'
port = 5656

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server_socket.bind((ip, port))
server_socket.listen()

# 서버에서 키 입력
password = input("Enter encryption key for server: ")
key = hashlib.sha256(password.encode()).digest()  # 고정된 32바이트 길이의 키 생성

print('Server started and listening')

while True:
    client_socket, addr = server_socket.accept()
    
    # 새로운 클라이언트를 위한 스레드 생성
    thread = threading.Thread(target=threaded, args=(client_socket, addr, key))
    thread.start()

while True:
    client_socket, addr = server_socket.accept()
    thread = threading.Thread(target=threaded, args=(client_socket, addr, key))
    thread.start()
