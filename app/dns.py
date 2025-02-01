import struct


class DNSMessage:
    # Packet Identifier
    ID = 1234
    # Query/Response Indicator (QR)
    # 1 for a reply packet, 0 for a question packet.
    # Since we're yielding replies, we keep this as 1.
    QR = 1

    # 1 stands for a host address question type (type A)
    # https://www.rfc-editor.org/rfc/rfc1035#section-3.2.2
    QUESTION_TYPE = 1

    # 1 stands for the internet (class IN)
    # https://www.rfc-editor.org/rfc/rfc1035#section-3.2.4
    QUESTION_CLASS = 1

    def create_header(self, question_count: int) -> bytes:
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
        flags1 = (self.QR << 7) | (0 << 3) | (0 << 2) | (0 << 1) | 0

        # 2nd flag - 8 bits
        # RA (1 bit): 0
        # Z (3 bits): 0
        # RCODE (4 bits): 0
        flags2 = (0 << 7) | (0)

        # Next four 16-bit fields
        qdcount = question_count  # Question Count
        ancount = 0  # Answer Record Count
        nscount = 0  # Authority Record Count
        arcount = 0  # Additional Record Count

        # Pack everything into a binary string
        # '!' means network byte order (big-endian)
        # 'H' means 16-bit unsigned short
        # 'BB' means two 8-bit unsigned chars (for the flags)
        # HBBHHHH = H + 2B + 4H = 2*1 + 5*2 = 12 bytes
        return struct.pack(
            "!HBBHHHH",
            self.ID,  # 16 bits
            flags1,  # 8 bits
            flags2,  # 8 bits
            qdcount,  # 16 bits
            ancount,  # 16 bits
            nscount,  # 16 bits
            arcount,  # 16 bits
        )

    def create_question(self) -> str:
        # For now we'll keep a hardcoded question
        question = "codecrafters.io"

        name = ""
        for label in question.split("."):
            length = chr(len(label))
            name += f"{length}{label}"
        name += "\x00"

        question_type = int(self.QUESTION_TYPE).to_bytes(length=2).decode()
        question_class = int(self.QUESTION_CLASS).to_bytes(length=2).decode()

        return name + question_type + question_class
