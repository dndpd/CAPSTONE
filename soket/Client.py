import socket
import hashlib

# 데이터를 SHA-256으로 해싱하는 함수
def hash_data(data):
    sha256 = hashlib.sha256()
    sha256.update(data)
    return sha256.hexdigest()

# 서버에 연결
server_ip = '127.0.0.1'
server_port = 8080

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((server_ip, server_port))

try:
    while True:
        # 사용자 입력을 받아서 전송
        message = input("Enter message to send (or 'exit' to quit): ")
        if message.lower() == 'exit':
            break

        # 입력된 메시지를 해싱하고 해시값과 함께 전송
        message_bytes = message.encode()
        message_hash = hash_data(message_bytes)
        client_socket.send(f"{message_hash}:{message}".encode())

        # 서버로부터의 응답 수신
        response = client_socket.recv(1024).decode()

        # 수신한 메시지를 해싱값과 분리
        received_hash = response.split(':')[0]
        server_message = ':'.join(response.split(':')[1:]).encode()

        # 서버로부터 받은 메시지의 해싱값을 확인
        calculated_hash = hash_data(server_message)

        if received_hash == calculated_hash:
            print(f"Server response: {server_message.decode()} (verified)")
        else:
            print(f"Server response: {server_message.decode()} (hash mismatch)")

finally:
    client_socket.close()
