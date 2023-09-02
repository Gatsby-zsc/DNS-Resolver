import socket
import sys


def print_usage():
    print("Error: invalid arguments")
    print("Usage: client resolver_ip resolver_port name [type=A] [rd] [timeout=5]")

def validate_query_type(query_type):
    valid_types = ['A', 'NS', 'CNAME', 'PTR', 'MX']
    return query_type.upper() in valid_types

def start_client(resolver_ip, resolver_port, name, query_type='A', timeout='5', rd=False):
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(int(timeout))
        client_socket.connect((resolver_ip, int(resolver_port)))

        message = f"{name} {query_type} {timeout} {rd}"
        client_socket.send(message.encode())
        response = client_socket.recv(1024).decode()

        print(response)

        client_socket.close()

    except Exception as e:
        print(f"Error: {str(e)}")


if __name__ == "__main__":
    if len(sys.argv) < 4 or len(sys.argv) > 7:
        print_usage()
        sys.exit(1)

    resolver_ip = sys.argv[1]
    resolver_port = sys.argv[2]
    name = sys.argv[3]
    query_type = 'A'
    timeout = '5'
    rd = False

    for arg in sys.argv[4:]:
        if validate_query_type(arg):
            query_type = arg
        elif arg == 'rd':
            rd = True
        else:
            try:
                timeout_value = int(arg)
                if timeout_value >= 5:
                    timeout = arg
                else:
                    print("Error: timeout is no less than 5")
                    sys.exit(1)
            except ValueError:
                print_usage()
                sys.exit(1)

    start_client(resolver_ip, resolver_port, name, query_type, timeout, rd)
