import socket
import threading
import time

from enum import Enum
from multipledispatch import dispatch
from datetime import datetime


TIMESTAMP_BASE = 2**7
TIMESTAMP_LEN = 5


def int_to_base(n: int, b: int) -> list[int]:
    if n == 0:
        return [0]

    digits = []
    while n:
        digits.append(n % b)
        n //= b

    return digits[::-1]

def base_to_decimal(digits: list[int], b: int) -> int:
    total = 0
    for i in range(len(digits)):
        total += digits[-i-1] * (b ** i)

    return total


class MessageType(Enum):
    URL = 0
    FILE = 1

class Message:
    @dispatch(str, MessageType, int)
    def __init__(self, data: str, message_type: MessageType, timestamp: int) -> None:
        self.data = data
        self.message_type = message_type
        self.timestamp = timestamp
        self.source = ""

    @dispatch(bytes)
    def __init__(self, message_bytes: bytes) -> None:
        self.data = message_bytes[TIMESTAMP_LEN + 1:].decode()
        self.message_type = MessageType(message_bytes[TIMESTAMP_LEN])
        self.timestamp = base_to_decimal(message_bytes[:TIMESTAMP_LEN], TIMESTAMP_BASE)
        self.source = ""

    def __repr__(self) -> str:
        timestamp = datetime.utcfromtimestamp(self.timestamp).strftime("%Y-%m-%d %H:%M:%S")

        return f"{self.source} at {timestamp}:\t{self.data}\t({self.message_type})"

    def __bytes__(self) -> bytes:
        timestamp = int_to_base(self.timestamp, TIMESTAMP_BASE)
        timestamp = [0]*(TIMESTAMP_LEN - len(timestamp)) + timestamp
        timestamp = "".join(chr(i) for i in timestamp)

        return f"{timestamp}{chr(self.message_type.value)}{self.data}".encode()


class Peer:
    def __init__(self) -> None:
        self.recv_socket = socket.socket()
        self.recv_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.recv_socket.bind(("", 8000))

        self.messages = []
        self.is_running = True

    def start(self) -> None:
        threading.Thread(target=self.send_loop).start()
        threading.Thread(target=self.recv_loop).start()


    def gen_key(self, ip: str) -> int:
        return -1

    def encrypt(self, data: bytes) -> bytes:
        return data


    def recv_message(self) -> Message:
        conn, addr = self.recv_socket.accept()

        data = conn.recv(1024)
        conn.close()

        message = Message(data)
        message.source = addr[0]

        return message

    def recv_loop(self) -> None:
        self.recv_socket.listen()
        while self.is_running:
            message = self.recv_message()
            if message.data:
                print("\a", end="")
                self.messages.append(message)
            else:
                self.is_running = False

            time.sleep(0.1)


    def send_message(self, ip: str, message: Message, *, encrypt: bool) -> None:
        message = bytes(message)
        if encrypt:
            key = self.gen_key(ip)
            message = self.encrypt(message)

        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.connect((ip, 8000))
        sock.send(message)
        sock.close()

    def send_loop(self) -> None:
        while self.is_running:
            data = input("mes: ")
            message_type = int(input("type: "))
            ip = input("ip: ")

            message = Message(data, MessageType(message_type), int(time.time()))
            try:
                self.send_message(ip, message, encrypt=True)
            except OSError:
                print("Invalid IP address.\n")

            time.sleep(0.1)

            print("\nmessages:")
            for mes in self.messages:
                print(f"\t{mes}")
            print()
