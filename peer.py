import socket
import threading
import time

from dataclasses import dataclass


@dataclass
class Message:
    data: bytes
    source: str


class Peer:
    def __init__(self) -> None:
        self.recv_socket = socket.socket()
        self.recv_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.recv_socket.bind(("", 7000))

        self.messages = []
        self.is_running = True

    def start(self) -> None:
        threading.Thread(target=self.send_loop).start()
        threading.Thread(target=self.recv_loop).start()


    def gen_key(self, ip: str) -> int:
        return -1

    def encrypt(self, data: bytes) -> bytes:
        return data


    def recv_data(self) -> Message:
        conn, addr = self.recv_socket.accept()

        data = conn.recv(1024)
        conn.close()

        message = Message(data, addr[0])

        return message

    def recv_loop(self) -> None:
        self.recv_socket.listen()
        while self.is_running:
            message = self.recv_data()
            if message.data:
                self.messages.append(message)
            else:
                self.is_running = False

            time.sleep(0.1)


    def send_data(self, ip: str, data: bytes, *, encrypt: bool) -> None:
        if encrypt:
            key = self.gen_key(ip)
            data = self.encrypt(data)

        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.connect((ip, 7000))
        sock.send(data)
        sock.close()

    def send_loop(self) -> None:
        while self.is_running:
            data = input("data: ").encode()
            ip = input("ip: ")

            try:
                self.send_data(ip, data, encrypt=True)
            except OSError:
                print("Invalid IP address.\n")

            time.sleep(0.1)
