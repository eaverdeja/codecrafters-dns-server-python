import socket
from argparse import ArgumentParser

from .dns import DNSMessage


def _run_server(udp_socket: socket.SocketType):
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)

            header = buf[: DNSMessage.HEADER_SIZE]
            query_header = DNSMessage.parse_header(header)

            offset = DNSMessage.HEADER_SIZE
            domain_names = []
            for _ in range(query_header.question_count):
                domain_name, offset = DNSMessage.parse_question(buf, offset=offset)
                domain_names.append(domain_name)

            response_header = DNSMessage.create_header(
                query_header,
                question_count=query_header.question_count,
                answer_count=len(domain_names),
            )
            messages = [
                DNSMessage(packet_id=query_header.packet_id, domain_name=domain_name)
                for domain_name in domain_names
            ]
            response = response_header
            questions, answers = [], []
            for message in messages:
                questions.append(message.create_question())
            for message in messages:
                answers.append(message.create_answer())

            response += "".join(questions).encode()
            response += "".join(answers).encode()

            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


def _run_forwarding_server(udp_socket: socket.SocketType, address: str, port: int):
    while True:
        # Receive
        buf, source = udp_socket.recvfrom(512)

        # Split questions
        ...

        # Forward
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client_socket.sendto(buf, (address, port))

        # Merge responses
        ...

        # Respond
        server_response = client_socket.recv(512)
        udp_socket.sendto(server_response, source)


def main():
    parser = ArgumentParser(description="Simple DNS server")
    parser.add_argument(
        "--resolver", type=str, help="The address of the resolver DNS server"
    )
    parser.add_argument(
        # Note: Standard DNS uses port 53, but that usually requires root privileges
        "--port",
        type=str,
        help="The port of the DNS server",
        default=2053,
    )
    args = parser.parse_args()

    # AF_INET means we're using IPv4
    # SOCK_DGRAM specifies UDP protocol (as opposed to TCP which would be SOCK_STREAM)
    # DGRAM stands for (User) DataGram (Protocol), or UDP for short ;)
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    udp_socket.bind(("127.0.0.1", int(args.port)))

    if args.resolver:
        address, port = args.resolver.split(":")
        _run_forwarding_server(udp_socket, address, int(port))
    else:
        _run_server(udp_socket)


if __name__ == "__main__":
    main()
