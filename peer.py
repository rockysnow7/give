import socket
import threading
import time
import math
import sympy
import random
import re
import os
import webbrowser

from enum import Enum
from multipledispatch import dispatch
from datetime import datetime


PORT_NUM = 8001

ENCODING_BASE = 2**7
TIMESTAMP_LEN = math.ceil(math.log(2**31, ENCODING_BASE))  # num digits to encode unix time
PG_UPPER_LIMIT = 2**10
PG_LEN = math.ceil(math.log(PG_UPPER_LIMIT, ENCODING_BASE))  # num digits to encode p, g
FILE_NAME_LEN = math.ceil(math.log(100, ENCODING_BASE))


def int_to_base(n: int, b: int) -> list[int]:
    """
    Converts an int into a list of digits in a given base.

    Args:
        n (int): the base 10 number to be changed.
        b (int): the base to which `n` will be changed.

    Returns:
        A list of digits (list[int]) representing the base `b` number.
    """

    if n == 0:
        return [0]

    digits = []
    while n:
        digits.append(n % b)
        n //= b

    return digits[::-1]

def base_to_decimal(digits: list[int], b: int) -> int:
    """
    Converts a list of digits in a given base into base 10.

    Args:
        digits (list[int]): the list of digits to convert into base 10.
        b (int): the base the digits are currently in.

    Returns:
        An int representing `digits` in base 10.
    """

    total = 0
    for i in range(len(digits)):
        total += digits[-i-1] * (b ** i)

    return total

def pad_digits(digits: list[int], n: int) -> list[int]:
    """
    Prepend zeros to a list of digits.

    Args:
        digits (list[int]): a list of digits.
        n (int): the desired final length, once zeros have been prepended.

    Returns:
        The same as `digits` but with zeros prepended to make it of length `n`.
    """

    return [0]*(n - len(digits)) + digits

def str_to_int(digits: str, b: int) -> int:
    """
    Interprets a string as a list of chars representing a base `b` number, and converts it to base 10.

    Args:
        digits (str): a string to be interpreted as digits.
        b (int): the base the digits are in.

    Returns:
        A base 10 int.
    """

    return base_to_decimal([ord(i) for i in digits], b)


def is_primitive_root_mod_n(g: int, n: int) -> bool:
    """
    Tests if an int `g` is a primitive root mod `n` by testing if every number coprime to `n` is congruent to a power of `g` mod `n`.

    Args:
        g (int): the number to be tested.
        n (int): the modulus.

    Returns:
        A bool representing whether `g` is a primitive root mod `n`.
    """

    if 0 <= g < n and math.gcd(g, n) == 1:
        for q in sympy.primefactors(sympy.totient(n)):
            if pow(g, sympy.totient(n) // q, n) == 1:
                return False
        return True
    return False

def get_primitive_roots_mod_n(n: int) -> list[int]:
    """
    Returns the list of primitive roots mod a given number.

    Args:
        n (int): the modulus.

    Returns:
        The list of primitive roots mod `n`.
    """

    return [i for i in range(n) if is_primitive_root_mod_n(i, n)]


class MessageType(Enum):
    KEY_EXCHANGE = 0
    OTHER = 1
    URL = 2
    FILE = 3

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
        data = self.data.encode()

        return f"{self.source} at {timestamp}:\t{data}\t({self.message_type})"

    def __bytes__(self) -> bytes:
        timestamp = int_to_base(self.timestamp, ENCODING_BASE)
        timestamp = pad_digits(timestamp, TIMESTAMP_LEN)
        timestamp = "".join(chr(i) for i in timestamp)

        return f"{timestamp}{chr(self.message_type.value)}{self.data}".encode()


class Peer:
    def __init__(self) -> None:
        self.recv_socket = socket.socket()
        self.recv_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.recv_socket.bind(("", PORT_NUM))

        self.keys = {}
        self.messages = []
        self.is_running = True

    def start(self) -> None:
        threading.Thread(target=self.send_loop).start()
        threading.Thread(target=self.recv_loop).start()

        while self.is_running:
            for ip in self.keys:
                if "ack" in self.keys[ip] and not self.keys[ip]["ack"]:
                    self.send_message(ip, self.keys[ip]["res"], encrypt=False)

            time.sleep(0.5)


    def init_key_gen(self, ip: str) -> None:
        """
        Initiates a Diffie-Hellman key exchange with a given IP address, in preparation for encrypting a message to send to that IP.

        Args:
            ip (str): the IP address with which to initiate the key exchange.
        """

        p = sympy.randprime(0, PG_UPPER_LIMIT)
        g = random.choice(get_primitive_roots_mod_n(p))

        if ip not in self.keys:
            self.keys[ip] = {}
        self.keys[ip]["p"] = p
        self.keys[ip]["g"] = g

        p = "".join(chr(i) for i in pad_digits(int_to_base(p, ENCODING_BASE), PG_LEN))
        g = "".join(chr(i) for i in pad_digits(int_to_base(g, ENCODING_BASE), PG_LEN))

        data = f"\x00{p}{g}"
        message = Message(data, MessageType.KEY_EXCHANGE, int(time.time()))
        self.send_message(ip, message, encrypt=False)

    def handle_key_gen(self, message: Message) -> None:
        """
        Handle a key exchange message from another IP address.

        Args:
            message (Message): the message containing info about the key exchange.
        """

        if message.source not in self.keys:
            self.keys[message.source] = {}

        if ord(message.data[0]) == 0:
            p = str_to_int(message.data[1:PG_LEN+1], ENCODING_BASE)
            g = str_to_int(message.data[PG_LEN+1:2*PG_LEN + 1], ENCODING_BASE)

            self.keys[message.source]["p"] = p
            self.keys[message.source]["g"] = g

            self.keys[message.source]["a"] = random.randint(0, PG_UPPER_LIMIT)
            A = pow(g, self.keys[message.source]["a"], p)
            A = "".join(chr(i) for i in pad_digits(int_to_base(A, ENCODING_BASE), PG_LEN))
            response = Message(f"\x01{A}", MessageType.KEY_EXCHANGE, int(time.time()))

            self.send_message(message.source, response, encrypt=False)

        elif ord(message.data[0]) == 1:
            A = str_to_int(message.data[1:], ENCODING_BASE)
            self.keys[message.source]["A"] = A

            b = random.randint(0, PG_UPPER_LIMIT)
            self.keys[message.source]["b"] = b

            B = pow(self.keys[message.source]["g"], b, self.keys[message.source]["p"])
            B = "".join(chr(i) for i in pad_digits(int_to_base(B, ENCODING_BASE), PG_LEN))
            response = Message(f"\x02{B}", MessageType.KEY_EXCHANGE, int(time.time()))

            s = pow(self.keys[message.source]["A"], b, self.keys[message.source]["p"])
            self.keys[message.source]["key"] = s

            self.keys[message.source]["ack"] = False
            self.keys[message.source]["res"] = response
            self.send_message(message.source, response, encrypt=False)

        elif ord(message.data[0]) == 2:
            B = str_to_int(message.data[1:], ENCODING_BASE)
            s = pow(B, self.keys[message.source]["a"], self.keys[message.source]["p"])
            self.keys[message.source]["key"] = s

            response = Message("\x03", MessageType.KEY_EXCHANGE, int(time.time()))
            self.send_message(message.source, response, encrypt=False)

        elif ord(message.data[0]) == 3:
            self.keys[message.source]["ack"] = True


    def encrypt(self, data: str, key: int) -> str:
        """
        Unimplemented. Will encrypt data given a key.

        Args:
            data (str): the data to encrypt.
            key (int): the key to be used in encryption.

        Returns:
            The encrypted form of the data.
        """

        return data

    def decrypt(self, data: str, key: int) -> str:
        """
        Unimplemented. Will decrypt data given a key.

        Args:
            data (str): encrypted data.
            key (int): the key used to decrypt the data.

        Returns:
            The decrypted form of the data.
        """

        return data


    def recv_message(self) -> Message:
        """
        Receives a message and adds any necessary data.

        Returns:
            A received message.
        """

        conn, addr = self.recv_socket.accept()

        data = conn.recv(1024)
        conn.close()

        message = Message(data)
        message.source = addr[0]

        return message

    def recv_loop(self) -> None:
        """One of the two main loops to be run. Handles received messages."""

        self.recv_socket.listen()
        while self.is_running:
            message = self.recv_message()
            if message.message_type != MessageType.KEY_EXCHANGE:
                message.data = self.decrypt(message.data, self.keys[message.source]["key"])

            if message.data:
                print("\a", end="")
                self.messages.append(message)

                if message.message_type == MessageType.KEY_EXCHANGE:
                    self.handle_key_gen(message)

                elif message.message_type == MessageType.URL:
                    choice = input(f"Open \"{message.data}\" (y/n)? ").lower()
                    if choice == "y":
                        webbrowser.open_new_tab(message.data)

                elif message.message_type == MessageType.FILE:
                    name_len = str_to_int(message.data[:FILE_NAME_LEN], ENCODING_BASE)
                    name = message.data[FILE_NAME_LEN:name_len+FILE_NAME_LEN]
                    choice = input(f"Download \"{name}\" (y/n)? ").lower()
                    if choice == "y":
                        path = input("Save to path: ") or "."
                        data = message.data[name_len+FILE_NAME_LEN:]
                        with open(os.path.join(path, name), "w+") as f:
                            f.write(data)
            else:
                self.is_running = False

            time.sleep(0.1)


    def send_message(self, ip: str, message: Message, *, encrypt: bool) -> None:
        """
        Sends a given message to a given IP address, optionally encrypting it.

        Args:
            ip (str): the IP address to which the message will be sent.
            message (Message): the message to be sent.
            encrypt (bool): whether or not to encrypt the message.
        """

        message = bytes(message)
        if encrypt:
            self.init_key_gen(ip)
            while ip not in self.keys or "key" not in self.keys[ip]:
                pass
            key = self.keys[ip]["key"]
            message = self.encrypt(message, key)

        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.connect((ip, PORT_NUM))
        sock.send(message)
        sock.close()

    def send_loop(self) -> None:
        """One of the two main loops to be run. Handles sending messages."""

        while self.is_running:
            message_type = input("type: ")
            if message_type == "url":
                message_type = MessageType.URL.value
                data = input("url: ")
            elif message_type == "file":
                message_type = MessageType.FILE.value

                path = input("path: ")
                name = re.split(r"[\/]", path)[-1]
                with open(path, "r") as f:
                    data = f.read()
                data = "".join(chr(i) for i in pad_digits(int_to_base(len(name), ENCODING_BASE), FILE_NAME_LEN)) + name + data
            else:
                message_type = MessageType.OTHER.value
                data = input("data: ")

            ip = input("ip: ")
            if ip in {"", "localhost"}:
                ip = "127.0.0.1"

            message = Message(data, MessageType(message_type), int(time.time()))
            try:
                self.send_message(ip, message, encrypt=True)
            except OSError:
                print("Invalid IP address.\n")

            time.sleep(0.5)
