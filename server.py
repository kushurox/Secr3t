import base64
import hashlib
import re
import socketserver


def make_payload(data: bytes):
    payload = bytearray([0, 0])
    payload[0] = 0b10000001  # setting op code to 0x1 and fin to 1
    payload[1] = len(data) & 0b01111111  # setting mask to 0
    return bytes(payload) + data


class Payload:
    FIN = 0b0  # 1 bit
    RSV1, RSV2, RSV3 = 0b0, 0b0, 0b0  # 3 bits - will be set to 0 since no extensions negotiated
    OPCODE = 0b0000  # 4 bits
    MASK = 0b0  # 1 bit
    PAYLOAD_LENGTH = 0b0000000  # 7 bits, Note: assuming length to be between 0-125
    MASKING_KEY = 0  # 4 bytes if masking bit = 1 else 0 bytes
    PAYLOAD_DATA = None  # x+y bytes  (assuming no extension data provided so x=0)

    def __init__(self, payload: bytes):
        self.payload = payload
        self.data = self.break_payload()

    def break_payload(self):
        OP_FIN = self.payload[0]  # first byte contains FIN/RSV values and the opcode
        self.FIN = OP_FIN >> 7
        self.OPCODE = OP_FIN & 0b00001111

        MASK_AND_PAYLOAD_LENGTH = self.payload[1]
        self.MASK = MASK_AND_PAYLOAD_LENGTH >> 7
        self.PAYLOAD_LENGTH = MASK_AND_PAYLOAD_LENGTH & 0b01111111
        if self.MASK:
            self.MASKING_KEY = self.payload[2:6]
            self.PAYLOAD_DATA = self.payload[6:]
        else:
            self.PAYLOAD_DATA = self.payload[2:]
        unmasked = bytearray()
        for i in range(self.PAYLOAD_LENGTH):
            unmasked.append(self.PAYLOAD_DATA[i] ^ self.MASKING_KEY[i % 4])

        return unmasked

    def __str__(self):
        return str(self.data)


def make_headers(headers: dict):
    result = ""
    result += "HTTP/1.1 101 Switching Protocols\r\n"
    for header, value in headers.items():
        result += f"{header}: {value}\r\n"
    return result + '\r\n'


def get_key(handshake_string):
    key = re.findall(r"Sec-WebSocket-Key: .*", handshake_string)[0]
    key = key.split(":")[1].strip()
    return key


class Handler(socketserver.BaseRequestHandler):
    MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    def handshake(self) -> None:
        handshake_text = self.request.recv(1024).decode('utf-8')
        print(handshake_text)
        key = get_key(handshake_text)
        key = key + self.MAGIC
        key = hashlib.sha1(key.encode()).digest()
        key = base64.b64encode(key).decode()

        headers = {"Upgrade": "websocket", "Connection": "Upgrade",
                   "Sec-WebSocket-Accept": key}

        headers = make_headers(headers)
        print('response')
        print(headers)
        self.request.sendall(headers.encode())

    def handle(self) -> None:
        self.handshake()
        print('handshake done!')
        while True:
            payload = Payload(self.request.recv(1024))
            print(payload)
            self.request.sendall(make_payload(b"data received lol"))

    def finish(self) -> None:
        print("Connection Over :(", self.client_address[0])


if __name__ == '__main__':
    socketserver.TCPServer.allow_reuse_address = True
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 2449), Handler)
    server.serve_forever()
