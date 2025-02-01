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
            data = buf[12:]

            query_header = DNSMessage.parse_header(header)
            domain_name = DNSMessage.parse_question(data)
            message = DNSMessage(
                packet_id=query_header.packet_id, domain_name=domain_name
            )

            response_header = message.create_header(
                query_header, question_count=1, answer_count=1
            )
            question = message.create_question()
            answer = message.create_answer()

            response = response_header + question.encode() + answer.encode()

            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
