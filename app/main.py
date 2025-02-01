import socket

from .dns import create_dns_header


def main():
    # AF_INET means we're using IPv4
    # SOCK_DGRAM specifies UDP protocol (as opposed to TCP which would be SOCK_STREAM)
    # DGRAM stands for (User) DataGram (Protocol), or UDP for short ;)
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Note: Standard DNS uses port 53, but that usually requires root privileges
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            header = create_dns_header()
            response = b"" + header

            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
