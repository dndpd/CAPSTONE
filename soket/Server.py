import socket
import threading
import hashlib

# 데이터를 SHA-256으로 해싱하는 함수
def hash_data(data):
    sha256 = hashlib.sha256()
    sha256.update(data)
    return sha256.hexdigest()

def threaded(client_socket, addr):
    print('Connected by: ', addr[0], ':', addr[1])

    while True:
        try:
            data = client_socket.recv(1024)  # 데이터를 받음
            if not data:
                print('Disconnected by ' + addr[0], ':', addr[1])
                break

            # 받은 데이터를 해싱
            received_hash = data.decode().split(':')[0]
            message = ':'.join(data.decode().split(':')[1:]).encode()

            # 받은 메시지를 다시 해싱하여 비교
            calculated_hash = hash_data(message)

            if received_hash == calculated_hash:
                print(f"Received valid data from {addr[0]}:{addr[1]}: {message.decode()}")
            else:
                print(f"Hash mismatch from {addr[0]}:{addr[1]}. Possible data corruption.")

            # 전송할 데이터를 해싱한 뒤 전송
            response = "Server received your message.".encode()
            response_hash = hash_data(response)
            client_socket.send(f"{response_hash}:{response.decode()}".encode())
        
        except ConnectionResetError as e:
            print("Disconnected by", addr[0], ':', addr[1])
            print(f"Error: {e}")
            break

# 서버 소켓 설정
ip = '127.0.0.1'
port = 8080

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# 소켓 에러 방지 옵션
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server_socket.bind((ip, port))
server_socket.listen()

print('Server start')

while True:
    client_socket, addr = server_socket.accept()
    print('Connected by', addr[0], ':', addr[1])
    
    # 새로운 클라이언트를 위한 스레드 생성
    thread = threading.Thread(target=threaded, args=(client_socket, addr))
    thread.start()
