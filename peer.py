import socket
import threading
import time
import math
import sympy
import random

from enum import Enum
from multipledispatch import dispatch
from datetime import datetime


ENCODING_BASE = 2**7
TIMESTAMP_LEN = math.ceil(math.log(2**31, ENCODING_BASE))  # num digits to encode unix time
PG_UPPER_LIMIT = 2**10
PG_LEN = math.ceil(math.log(PG_UPPER_LIMIT, ENCODING_BASE))  # num digits to encode p, g


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

def pad_digits(digits: list[int], n: int) -> list[int]:
    return [0]*(n - len(digits)) + digits


def is_primitive_root_mod_n(g: int, n: int) -> bool:
    if 0 <= g < n and math.gcd(g, n) == 1:
        for q in sympy.primefactors(sympy.totient(n)):
            #if (g ** (sympy.totient(n) / q)) % n == 1:
            if pow(g, int(sympy.totient(n) / q), n) == 1:
                return False
        return True
    return False

def get_primitive_roots_mod_n(n: int) -> list[int]:
    return [i for i in range(n) if is_primitive_root_mod_n(i, n)]


class MessageType(Enum):
    KEY_EXCHANGE = 0
    URL = 1
    FILE = 2

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
        self.timestamp = base_to_decimal(message_bytes[:TIMESTAMP_LEN], ENCODING_BASE)
        self.source = ""

    def __repr__(self) -> str:
        timestamp = datetime.utcfromtimestamp(self.timestamp).strftime("%Y-%m-%d %H:%M:%S")

        return f"{self.source} at {timestamp}:\t{self.data}\t({self.message_type})"

    def __bytes__(self) -> bytes:
        timestamp = int_to_base(self.timestamp, ENCODING_BASE)
        timestamp = pad_digits(timestamp, TIMESTAMP_LEN)
        timestamp = "".join(chr(i) for i in timestamp)

        return f"{timestamp}{chr(self.message_type.value)}{self.data}".encode()


class Peer:
    def __init__(self) -> None:
        self.recv_socket = socket.socket()
        self.recv_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.recv_socket.bind(("", 8000))

        self.keys = {}
        self.messages = []
        self.is_running = True

    def start(self) -> None:
        threading.Thread(target=self.send_loop).start()
        threading.Thread(target=self.recv_loop).start()


    def init_key_gen(self, ip: str) -> int:
        p = sympy.randprime(0, PG_UPPER_LIMIT)
        g = random.choice(get_primitive_roots_mod_n(p))
        print(f"{p=}, {g=}")

        p = "".join(chr(i) for i in pad_digits(int_to_base(p, ENCODING_BASE), PG_LEN))
        g = "".join(chr(i) for i in pad_digits(int_to_base(g, ENCODING_BASE), PG_LEN))

        data = f"\x00{p}{g}"
        message = Message(data, MessageType.KEY_EXCHANGE, int(time.time()))
        self.send_message(ip, message, encrypt=False)

        return -1

    def handle_key_gen(self, message: Message) -> None:
        if ord(message.data[0]) == 0:
            p = base_to_decimal([ord(i) for i in message.data[1:PG_LEN+1]], ENCODING_BASE)
            g = base_to_decimal([ord(i) for i in message.data[PG_LEN+1:2*PG_LEN + 1]], ENCODING_BASE)
            print(f"{p=}, {g=}")

            if message.source not in self.keys:
                self.keys[message.source] = {}
            self.keys[message.source]["a"] = random.randint(0, PG_UPPER_LIMIT)
            A = self.keys[message.source]["a"] = pow(g, self.keys[message.source]["a"], p)
            A = "".join(chr(i) for i in pad_digits(int_to_base(A, ENCODING_BASE), PG_LEN))
            response = Message(f"\x01{A}", MessageType.KEY_EXCHANGE, int(time.time()))
            
            self.send_message(message.source, response, encrypt=False)

    def encrypt(self, data: bytes, key: int) -> bytes:
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

                if message.message_type == MessageType.KEY_EXCHANGE:
                    self.handle_key_gen(message)
            else:
                self.is_running = False

            time.sleep(0.1)


    def send_message(self, ip: str, message: Message, *, encrypt: bool) -> None:
        message = bytes(message)
        if encrypt:
            key = self.init_key_gen(ip)
            message = self.encrypt(message, -1)

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
