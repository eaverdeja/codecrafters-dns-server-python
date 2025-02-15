import struct
from dataclasses import dataclass


@dataclass
class DNSHeader:
    packet_id: int
    operation_code: int
    recursion_desired: int
    response_code: int
    question_count: int


class DNSMessage:
    # Packet Identifier
    ID: int

    # Query/Response Indicator (QR)
    # 1 for a reply packet, 0 for a question packet.
    # Since we're yielding replies, we default this to 1.
    QR: int = 1

    # 1 stands for a host address question type (type A)
    # https://www.rfc-editor.org/rfc/rfc1035#section-3.2.2
    TYPE = 1

    # 1 stands for the internet (class IN)
    # https://www.rfc-editor.org/rfc/rfc1035#section-3.2.4
    CLASS = 1

    # The duration in seconds a record can be cached before requerying.
    # https://www.rfc-editor.org/rfc/rfc1035#section-3.2.1
    TTL = 60

    # https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1
    HEADER_FORMAT = "!HBBHHHH"
    HEADER_SIZE = 12

    # https://www.rfc-editor.org/rfc/rfc1035#section-4.1.4
    IS_COMPRESSED_LABEL_MASK = 0b1100_0000
    LABEL_POINTER_MASK = 0b0011_1111

    def __init__(self, packet_id: int, indicator: int = 1):
        self.ID = packet_id
        self.QR = indicator

    def create_header(
        self, query_header: DNSHeader, question_count: int, answer_count: int
    ) -> bytes:
        """
        Creates a 12-byte DNS header with the specified fields.
        All integers are encoded in big-endian format.

        Returns:
            bytes: A 12-byte header conforming to the DNS specification
        """
        # First 16 bits come from our ID
        # ...
        # The next 16 bits come from various flags
        # We'll construct this using binary operations
        #
        # 1st flag - 8 bits
        # QR (1 bit): 1
        # OPCODE (4 bits): 0
        # AA (1 bit): 0
        # TC (1 bit): 0
        # RD (1 bit): 0
        # The bit shifting is a bit easier this to visualize if
        # all flags have their bits set:
        # 10000000  (qr) 1 << 7
        # 00001000  (opcode) 1 << 3
        # 00000100  (aa) 1 << 2
        # 00000010  (tc) 1 << 1
        # 00000001  (rd) 1
        # --------  OR them together (|)
        # 10001111  = 143 in decimal
        #
        flags1 = (
            (self.QR << 7)
            | (query_header.operation_code << 3)
            | (0 << 2)
            | (0 << 1)
            | query_header.recursion_desired
        )

        # 2nd flag - 8 bits
        # RA (1 bit): 0
        # Z (3 bits): 0
        # RCODE (4 bits): 0
        flags2 = (0 << 7) | query_header.response_code

        # Next four 16-bit fields
        qdcount = question_count  # Question Count
        ancount = answer_count  # Answer Record Count
        nscount = 0  # Authority Record Count
        arcount = 0  # Additional Record Count

        # Pack everything into a binary string
        # '!' means network byte order (big-endian)
        # 'H' means 16-bit unsigned short
        # 'BB' means two 8-bit unsigned chars (for the flags)
        # HBBHHHH = H + 2B + 4H = 2*1 + 5*2 = 12 bytes
        return struct.pack(
            self.HEADER_FORMAT,
            query_header.packet_id,  # 16 bits
            flags1,  # 8 bits
            flags2,  # 8 bits
            qdcount,  # 16 bits
            ancount,  # 16 bits
            nscount,  # 16 bits
            arcount,  # 16 bits
        )

    def create_question(self, domain_name: str) -> str:
        name = self._as_label_sequence(domain_name)

        question_type = self._as_string_of_bytes(self.TYPE, length=2)
        question_class = self._as_string_of_bytes(self.CLASS, length=2)

        return name + question_type + question_class

    def create_answer(self, domain_name: str) -> str:
        name = self._as_label_sequence(domain_name)

        answer_type = self._as_string_of_bytes(self.TYPE, length=2)
        answer_class = self._as_string_of_bytes(self.CLASS, length=2)
        ttl = self._as_string_of_bytes(60, length=4)

        # For now we'll keep a hardcoded IP address
        ip_address = "8.8.8.8"
        data = "".join([chr(int(piece)) for piece in ip_address.split(".")])
        length = self._as_string_of_bytes(len(data), length=2)

        return name + answer_type + answer_class + ttl + length + data

    @classmethod
    def parse_header(cls, header: bytes) -> DNSHeader:
        packet_id, flags1, _flags2, qdcount, _ancount, _nsacount, _arcount = (
            struct.unpack(cls.HEADER_FORMAT, header)
        )
        # Recall that OPCODE is shifted 3 positions to the left
        # We need to shift it to the right before applying our mask
        opcode = (flags1 >> 3) & 0b00001111
        # RD is our least significant bit - no shifting required
        rd_bit = flags1 & 0b00000001
        # 0 (no error) if OPCODE is 0 (standard query) else 4 (not implemented)
        rcode = 0 if opcode == 0 else 4

        return DNSHeader(
            packet_id=packet_id,
            operation_code=opcode,
            recursion_desired=rd_bit,
            response_code=rcode,
            question_count=qdcount,
        )

    @classmethod
    def parse_question(cls, packet: bytes, offset: int) -> tuple[str, int]:
        pieces = []

        # Labels end at a null byte
        while (length := packet[offset]) != 0:
            if offset + length >= len(packet) - 1:
                # Avoid overflowing
                break

            if cls._is_compressed_label(length):
                piece, offset = cls._follow_label_pointer(packet, offset, length)
            else:
                piece, offset = cls._decode_label(packet, offset, length)
            pieces.append(piece)

        # Skip the 4 bytes for TYPE and CLASS, plus a byte for the null terminator
        offset += 4 + 1

        return ".".join(pieces), offset

    @classmethod
    def parse_answer(cls, packet: bytes, offset: int) -> tuple[str, int]:
        print("packet ", packet)
        print("offset ", offset)
        return packet.decode(), offset

    @classmethod
    def _is_compressed_label(cls, length: int) -> bool:
        return bool(length & cls.IS_COMPRESSED_LABEL_MASK)

    @classmethod
    def _decode_label(cls, packet: bytes, offset: int, length: int) -> tuple[str, int]:
        offset += 1
        data = packet[offset : offset + length]
        offset += length
        return data.decode(), offset

    @classmethod
    def _follow_label_pointer(cls, packet: bytes, offset: int, length: int):
        offset += 1
        new_offset = ((length & cls.LABEL_POINTER_MASK) << 8) | packet[offset]
        return cls.parse_question(packet, new_offset)

    def _as_label_sequence(self, name: str) -> str:
        result = ""
        for label in name.split("."):
            length = chr(len(label))
            result += f"{length}{label}"
        result += "\x00"
        return result

    def _as_string_of_bytes(self, number: int, length: int) -> str:
        return number.to_bytes(length=length).decode()
