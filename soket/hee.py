import socket
import threading
import hashlib

# 클라이언트와 통신하는 스레드 함수
def threaded(client_socket, addr):
    print(f'Connected by: {addr[0]}:{addr[1]}')

    while True:
        try:
            # 클라이언트로부터 평문 데이터를 수신
            data = client_socket.recv(1024)
            if not data:
                print(f'Disconnected by {addr[0]}:{addr[1]}')
                break

            # 받은 평문 데이터를 출력
            message = data.decode()
            print(f"Message from {addr[0]}:{addr[1]}: {message}")
                
            # 응답도 평문으로 전송
            response = "Message received successfully."
            client_socket.send(response.encode())

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

print('Server started and listening')

while True:
    client_socket, addr = server_socket.accept()
    
    # 새로운 클라이언트를 위한 스레드 생성
    thread = threading.Thread(target=threaded, args=(client_socket, addr))
    thread.start()
