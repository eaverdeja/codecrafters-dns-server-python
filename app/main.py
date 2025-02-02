import socket

from .dns import DNSMessage


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
            # The DNS packet header is always 12 bytes in length
            header = buf[:12]

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


if __name__ == "__main__":
    main()
