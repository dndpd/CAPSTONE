import socket
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

# 서버에 연결
server_ip = '127.0.0.1'
server_port = 8080

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((server_ip, server_port))

# 키 입력 (서버와 동일한 16바이트 AES 키)
key_input = input("Enter a 16-byte key for encryption: ")
key = key_input.encode()  # 문자열을 바이트로 변환

try:
    while True:
        # 사용자 입력을 받아서 암호화 후 전송
        message = input("Enter message to send (or 'exit' to quit): ")
        if message.lower() == 'exit':
            break

        encrypted_message = encrypt_data(key, message)
        client_socket.send(encrypted_message)

        # 서버로부터의 응답 수신 및 복호화
        response = client_socket.recv(1024)
        decrypted_response = decrypt_data(key, response)
        print(f"Server response: {decrypted_response}")

finally:
    client_socket.close()
