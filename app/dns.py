import struct


def create_dns_header() -> bytes:
    """
    Creates a 12-byte DNS header with the specified fields.
    All integers are encoded in big-endian format.

    Returns:
        bytes: A 12-byte header conforming to the DNS specification
    """
    # First 16 bits: Packet Identifier (ID)
    id = 1234

    # Next 16 bits: Various flags
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
    flags1 = (1 << 7) | (0 << 3) | (0 << 2) | (0 << 1) | 0

    # 2nd flag - 8 bits
    # RA (1 bit): 0
    # Z (3 bits): 0
    # RCODE (4 bits): 0
    flags2 = (0 << 7) | (0)

    # Next four 16-bit fields
    qdcount = 0  # Question Count
    ancount = 0  # Answer Record Count
    nscount = 0  # Authority Record Count
    arcount = 0  # Additional Record Count

    # Pack everything into a binary string
    # '!' means network byte order (big-endian)
    # 'H' means 16-bit unsigned short
    # 'BB' means two 8-bit unsigned chars (for the flags)
    return struct.pack(
        "!HBBHHHH",
        id,  # 16 bits
        flags1,  # 8 bits
        flags2,  # 8 bits
        qdcount,  # 16 bits
        ancount,  # 16 bits
        nscount,  # 16 bits
        arcount,  # 16 bits
    )
