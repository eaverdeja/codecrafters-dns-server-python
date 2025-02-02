import socket
from argparse import ArgumentParser

from .dns import DNSHeader, DNSMessage


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

            response_header = DNSMessage(query_header.packet_id).create_header(
                query_header,
                question_count=query_header.question_count,
                answer_count=len(domain_names),
            )
            questions, answers = [], []
            for domain_name in domain_names:
                message = DNSMessage(packet_id=query_header.packet_id)
                questions.append(message.create_question(domain_name))
                answers.append(message.create_answer(domain_name))

            response = response_header
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

        header = buf[: DNSMessage.HEADER_SIZE]
        query_header = DNSMessage.parse_header(header)

        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        if query_header.question_count > 1:
            offset = DNSMessage.HEADER_SIZE

            # Split questions
            answers = []
            for _ in range(query_header.question_count):
                domain_name, offset = DNSMessage.parse_question(buf, offset=offset)
                # Question header
                request_header = DNSMessage(
                    query_header.packet_id, indicator=0
                ).create_header(
                    DNSHeader(
                        packet_id=query_header.packet_id,
                        operation_code=query_header.operation_code,
                        recursion_desired=query_header.recursion_desired,
                        response_code=query_header.response_code,
                        question_count=1,
                    ),
                    question_count=1,
                    answer_count=1,
                )
                message = DNSMessage(
                    packet_id=query_header.packet_id,
                )
                request = request_header + message.create_question(domain_name).encode()
                # Forward request
                client_socket.sendto(request, (address, port))

                # Receive
                answers.append(client_socket.recv(512))

            # Build the response header with the updated answer count
            response_header = DNSMessage(query_header.packet_id).create_header(
                DNSHeader(
                    packet_id=query_header.packet_id,
                    operation_code=query_header.operation_code,
                    recursion_desired=query_header.recursion_desired,
                    response_code=query_header.response_code,
                    question_count=query_header.question_count,
                ),
                question_count=query_header.question_count,
                answer_count=len(answers),
            )
            final_response = response_header

            # Merge answers back together with their respective questions
            for answer in answers:
                # Question
                offset = DNSMessage.HEADER_SIZE
                domain_name, offset = DNSMessage.parse_question(answer, offset=offset)
                message = DNSMessage(packet_id=query_header.packet_id)
                final_response += message.create_question(domain_name).encode()
                # Answer
                final_response += answer[DNSMessage.HEADER_SIZE :]

            # Forward
            udp_socket.sendto(final_response, source)
        else:
            # Forward buf as is
            client_socket.sendto(buf, (address, port))
            # Receive
            server_response = client_socket.recv(512)
            # Respond
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
