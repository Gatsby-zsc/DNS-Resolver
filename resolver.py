import socket
import struct
import time
import sys


def load_root_servers(filename):
    root_servers = []
    with open(filename, 'r') as f:
        for line in f.readlines():
            if line.startswith(';') or line.strip() == '':
                continue
            fields = line.split()
            if fields[2] == 'A':
                root_servers.append(fields[3])
    return root_servers


def build_query(domain, query_type='A', rd=False):
    domain += '.'
    QID = 0x1234
    FLAGS = 0x0000
    if rd:
        FLAGS |= 0x0100  # 设置RD（递归期望）标志位
    QDCOUNT = 1
    header = struct.pack('!HHHHHH', QID, FLAGS, QDCOUNT, 0, 0, 0)
    query_body = b''.join(struct.pack('B', len(part)) + part.encode() for part in domain.split('.'))

    # Define the query type
    type_code = 0x0001  # Default is A
    if query_type == 'NS':
        type_code = 0x0002
    elif query_type == 'CNAME':
        type_code = 0x0005
    elif query_type == 'PTR':
        type_code = 0x000C
    elif query_type == 'MX':
        type_code = 0x000F

    query_body += struct.pack('!HH', type_code, 0x0001)  # TYPE and CLASS (IN)
    return header + query_body


def parse_name(response, index):
    name, jumps, initial_index = "", 0, index
    while True:
        if index >= len(response):  # 检查索引是否超出范围
            raise Exception("Index out of range while parsing name.")

        length = response[index]
        if length >= 0xC0:
            if jumps == 0:
                initial_index = index + 2
            pointer_offset = ((length & 0x3F) << 8) + response[index + 1]
            if pointer_offset >= len(response) or pointer_offset >= index:  # 检查指针偏移是否超出范围或指向后面的位置
                raise Exception("Pointer offset out of range while parsing name.")
            index = pointer_offset
            jumps += 1
            if jumps > 5:
                raise Exception("Too many jumps, possible loop detected.")
            continue
        if length == 0:
            break
        index += 1
        segment = response[index: index + length]
        name += segment.decode('utf-8', 'replace') + "."  # 使用'replace'选项来处理非UTF-8字符
        index += length
    return name[:-1], index + 1 if jumps == 0 else initial_index


def parse_section(response, count, index):
    records = []
    for _ in range(count):
        name, index = parse_name(response, index)
        rtype, rclass, ttl, data_length = struct.unpack('!HHIH', response[index:index + 10])
        index += 10
        rdata = response[index:index + data_length]
        if rtype == 1:  # A
            ip_address = ".".join(str(b) for b in rdata)
            records.append((name, ttl, "IN", "A", ip_address))
        elif rtype == 2:  # NS
            ns_name, _ = parse_name(response, index)
            records.append((name, ttl, "IN", "NS", ns_name))
        elif rtype == 5:  # CNAME
            cname, _ = parse_name(response, index)
            records.append((name, ttl, "IN", "CNAME", cname))
        elif rtype == 15:  # MX
            preference = struct.unpack('!H', rdata[:2])[0]
            exchange, _ = parse_name(response, index + 2)
            records.append((name, ttl, "IN", "MX", (preference, exchange)))
        elif rtype == 12:  # PTR
            ptr_name, _ = parse_name(response, index)
            records.append((name, ttl, "IN", "PTR", ptr_name))
        index += data_length
    return records, index


def parse_response(response):
    header = struct.unpack('!HHHHHH', response[:12])
    index = 12
    question, index = parse_name(response, index)
    index += 4

    answer_records, index = parse_section(response, header[3], index)
    authority_records, index = parse_section(response, header[4], index)
    additional_records, index = parse_section(response, header[5], index)

    return question, answer_records, authority_records, additional_records, header


def try_query(query, servers, timeout=5):
    for server in servers:
        start_time = time.time()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(int(timeout))
            sock.sendto(query, (server, 53))
            response, _ = sock.recvfrom(512)
            sock.close()
            query_time = (time.time() - start_time) * 1000  # 转换为毫秒
            return response, server, query_time
        except socket.timeout:
            continue
    return None, None, None


def iterative_authority_query(domain, servers):
    query = build_query(domain, 'A')
    response, server, query_time = try_query(query, servers)
    total_query_time = query_time
    question, answer_records, authority_records, additional_records, header = parse_response(response)

    while authority_records:
        ns_servers = [ar[4] for ar in additional_records if ar[3] == "A"]
        response, server, query_time = try_query(query, ns_servers)
        if query_time:
            total_query_time += query_time
        else:
            return []
        question, answer_records, authority_records, additional_records, header = parse_response(response)

    return answer_records


def iterative_query(domain, servers, query_type, timeout, rd):
    original_domain = domain
    seen_domains = set()
    while True:
        query = build_query(domain, query_type, rd)
        response, server, query_time = try_query(query, servers, timeout)
        total_query_time = query_time
        question, answer_records, authority_records, additional_records, header = parse_response(response)
        while authority_records and not answer_records:
            ns_servers = [ar[4] for ar in additional_records if ar[3] == "A"]
            ns_domains = [ar[4] for ar in authority_records if ar[3] == "NS"]
            if not ns_servers:
                # 如果附加区域没有A记录，需要查询权威区域中NS记录的A类型
                for ns_domain in ns_domains:
                    ns_answer_records = iterative_authority_query(ns_domain, servers)
                    if ns_answer_records:
                        ns_servers += [rec[4] for rec in ns_answer_records if rec[3] == 'A']
                        break
            response, server, query_time = try_query(query, ns_servers)
            if query_time:
                total_query_time += query_time
            else:
                return None, server, 0, None, header
            question, answer_records, authority_records, additional_records, header = parse_response(response)

        # 查找CNAME记录，如果找到则重新查询
        if query_type != 'CNAME' and any(record[3] == "CNAME" for record in answer_records):
            cname_record = next(record for record in answer_records if record[3] == "CNAME")
            domain = cname_record[4]

            # 避免潜在的无限循环
            if domain in seen_domains:
                raise Exception(f"Loop detected in CNAME records for {original_domain}")
            seen_domains.add(domain)
            continue

        return (question, answer_records, authority_records, additional_records), server, len(
            response), total_query_time, header


def format_header(header):
    id, flags, qdcount, ancount, nscount, arcount = header

    opcode = "QUERY"
    rcode = flags & 0x000F
    status = "NOERROR"
    if rcode == 1:
        status = "FORMAT_ERROR"
    elif rcode == 2:
        status = "SERVER_FAILURE"
    elif rcode == 3:
        status = "NXDOMAIN"
    elif rcode == 4:
        status = 'NOT_IMPLEMENT'
    elif rcode == 5:
        status = 'REFUSED'
    elif rcode >= 6 and rcode <= 15:
        status = 'RESERVED'


    qr = (flags & 0x8000) != 0
    rd = (flags & 0x0100) != 0
    ra = (flags & 0x0080) != 0
    aa = (flags & 0x0400) != 0

    header_output = f";; -->>HEADER<<-- opcode: {opcode}, status: {status}, id: {id}\n"
    header_output += ";; flags:"
    if qr: header_output += " qr"
    if rd: header_output += " rd"
    if ra: header_output += " ra"
    if aa: header_output += " aa"
    header_output += f"; QUERY: {qdcount}, ANSWER: {ancount}, AUTHORITY: {nscount}, ADDITIONAL: {arcount}"

    return header_output


def format_output(query_result, server, msg_size, query_time, header, query_type):
    question, answer_records, authority_records, additional_records = query_result
    formatted_header = format_header(header)
    output = f";>> COMP9331 <<\n"
    output += f"{formatted_header}\n\n"
    output += f";; QUESTION SECTION:\n;{question}.\t\tIN\t\t{query_type}\n\n"
    if answer_records:
        output += ";; ANSWER SECTION:\n" + "\n".join(
            f"{n[0]}.\t\t{n[1]}\t\t{n[2]}\t\t{n[3]}\t\t{n[4]}" for n in answer_records) + "\n\n"
    if authority_records:
        output += ";; AUTHORITY SECTION:\n" + "\n".join(
            f"{n[0]}.\t\t{n[1]}\t\t{n[2]}\t\t{n[3]}\t\t{n[4]}." for n in authority_records) + "\n\n"
    if additional_records:
        output += ";; ADDITIONAL SECTION:\n" + "\n".join(
            f"{n[0]}.\t\t{n[1]}\t\t{n[2]}\t\t{n[3]}\t\t{n[4]}" for n in additional_records) + "\n\n"
    output += f";; Query time: {query_time:.2f} msec\n"
    output += f";; SERVER: {server}#53({server})\n"
    output += f";; WHEN: {time.strftime('%a %b %d %H:%M:%S AEST %Y')}\n"
    output += f";; MSG SIZE\trcvd: {msg_size}\n"
    return output


def handle_client_query(query):
    message = query.strip().split()
    domain = message[0]
    root_servers = load_root_servers('named.root')
    query_type = message[1]
    timeout = message[2]
    if message[3] == 'False':
        rd = False
    else:
        rd = True
    query_result, server, msg_size, query_time, header = iterative_query(domain, root_servers, query_type, timeout, rd)
    if query_result is None:  # 查询失败
        return "Error: server failure"

    rcode = header[1] & 0x000F
    status = None
    if rcode == 1:
        return f'Error: {domain} format error'
    elif rcode == 3:
        return f"Error: server can't find {domain}"
    elif rcode >= 4:
        if rcode == 4:
            status = 'NOT_IMPLEMENT'
        elif rcode == 5:
            status = 'REFUSED'
        elif 6 <= rcode <= 15:
            status = 'RESERVED'
        return f'Error: error code {rcode} {status}'

    return format_output(query_result, server, msg_size, query_time, header, query_type)


def start_server(port):
    host = '127.0.0.1'

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))

    server_socket.listen(1)
    print('Server is listening on port', port)

    while True:  # 外部循环用于持续监听新的连接
        conn, address = server_socket.accept()
        print('Connection from', address)

        while True:  # 内部循环用于处理来自当前连接的所有请求
            data = conn.recv(1024).decode()
            if not data:
                break
            print('Received from client: ' + data)

            result = handle_client_query(data)
            conn.send(result.encode())

        conn.close()


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Error: invalid arguments')
        print('Usage: resolver port')
        sys.exit(1)

    port = int(sys.argv[1])

    if port < 1024 or port > 65535:
        print('Error: Port number must be in the range 1024-65535')
        sys.exit(1)

    start_server(port)
