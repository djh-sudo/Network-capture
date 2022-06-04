import struct
from socket import ntohs, ntohl
from protocol_format import Protocol
import re


def handle_raw_data(raw_data, pro: Protocol):
    flag = handle_ethenet(raw_data[0:14], pro)
    if flag == 0x0800:
        protocol, header_len = handle_ip(raw_data[14:], pro)
        if protocol == 6:
            pro.protocol = 'TCP'
            tcp_header_len = handle_tcp(raw_data[14 + header_len:], pro)
            if tcp_header_len:
                res = handle_tcp_payload(raw_data, 14 + header_len + tcp_header_len, pro)
                if res:
                    return res
                else:
                    return True
            else:
                return True
        elif protocol == 17:
            pro.protocol = 'UDP'
            handle_udp(raw_data[14 + header_len:], pro)
            isOICQ(raw_data[14 + header_len + 8:], pro)
            return True
        elif protocol == 1:
            pro.protocol = 'ICMP'
        return True
    elif flag == 0x0806:
        handle_arp(raw_data[14:], pro)
        return True
    else:
        return False


def handle_tcp_payload(raw_data, offset, pro: Protocol):
    http = handle_http(raw_data[offset:], pro)
    if http:
        return http
    else:
        return handle_raw_tls(raw_data[offset:], pro)


def handle_raw_tls(raw_data, pro: Protocol):
    tls_len = handle_tls(raw_data, pro)
    if tls_len:
        flag = pro.assemble_payload_len - tls_len
        total_len = tls_len
        while flag > 0:
            tls_len = handle_sub_tls(raw_data[total_len:], pro)
            if tls_len:
                flag -= tls_len
                total_len += tls_len
            else:
                break
        return total_len
    else:
        return False


def handle_http(raw_data, pro: Protocol):
    http_len = handle_raw_http(raw_data, pro)
    if http_len:
        flag = pro.assemble_payload_len - http_len
        total_len = http_len
        while flag > 0:
            http_len = handle_sub_http(raw_data[total_len:], pro)
            if http_len:
                flag -= http_len
                total_len += http_len
            else:
                break
        if flag == 0:
            pro.protocol = 'TCP(HTTP)'
            sub_raw_data = str(raw_data, 'utf-8', errors='ignore')
            pro.info = sub_raw_data.split('\r\n')[0]
        return total_len
    else:
        return False


def handle_raw_http(raw_data, pro: Protocol):
    raw_data = str(raw_data, 'utf-8', errors='ignore')
    if 'HTTP' not in raw_data:
        return False
    if 'Content-Length' in raw_data:
        pattern = re.compile(r'Content-Length:.*\r\n')
        data_len = re.findall(pattern, raw_data)[0]
        data_len = int(data_len.split(':')[-1].split('\r')[0].replace(' ', ''))
        return len(raw_data.split('\r\n\r\n')[0]) + data_len + 4
    else:
        return len(raw_data)


def handle_sub_http(raw_data, pro: Protocol):
    raw_data = str(raw_data, 'utf-8', errors='ignore')
    if 'HTTP' not in raw_data:
        return False
    if 'Content-Length' in raw_data:
        pattern = re.compile(r'Content-Length:.*\r\n')
        data_len = re.findall(pattern, raw_data)[0]
        data_len = int(data_len.split(':')[-1].split('\r')[0].replace(' ', ''))
        if len(raw_data) >= len(raw_data.split('\r\n\r\n')[0]) + data_len + 4:
            return len(raw_data.split('\r\n\r\n')[0]) + data_len + 4
        else:
            return False
    else:
        return len(raw_data)


def handle_ethenet(raw_data, pro: Protocol):
    type = ntohs(struct.unpack('H', raw_data[12:14])[0])
    # 暂时指处理IEEE 802.3协议
    if type == 0x0800:
        des_mac_addr = struct.unpack('BBBBBB', raw_data[0:6])
        src_mac_addr = struct.unpack('BBBBBB', raw_data[6:12])
        des = []
        src = []
        for i in des_mac_addr:
            val = hex(i)
            val = val.replace('0x', '').zfill(2)
            des.append(val)
        des = ':'.join(des)
        pro.des_mac = des
        pro.des_ip = des

        for i in src_mac_addr:
            val = hex(i)
            val = val.replace('0x', '').zfill(2)
            src.append(val)
        src = ':'.join(src)

        pro.src_mac = src
        pro.src_ip = src
        pro.protocol = 'IPv4'
        return type
    elif type == 0x0806:
        des_mac_addr = struct.unpack('BBBBBB', raw_data[0:6])
        src_mac_addr = struct.unpack('BBBBBB', raw_data[6:12])
        des = []
        src = []
        for i in des_mac_addr:
            val = hex(i)
            val = val.replace('0x', '').zfill(2)
            des.append(val)
        des = ':'.join(des)
        pro.des_mac = des
        pro.des_ip = des

        for i in src_mac_addr:
            val = hex(i)
            val = val.replace('0x', '').zfill(2)
            src.append(val)
        src = ':'.join(src)

        pro.src_mac = src
        pro.src_ip = src
        pro.protocol = 'ARP'
        return type
    return 0


def handle_arp(raw_data, pro: Protocol):
    # hardware_type = ntohs(struct.unpack('H', raw_data[0:2])[0])
    # protocol_type = ntohs(struct.unpack('H', raw_data[2:4])[0])
    # harware_size = raw_data[4]
    # protocol_size = raw_data[5]
    op_code = ntohs(struct.unpack('H', raw_data[6:8])[0])
    sender_mac = struct.unpack('BBBBBB', raw_data[8:14])
    send_ip = struct.unpack('BBBB', raw_data[14:18])
    recv_mac = struct.unpack('BBBBBB', raw_data[18:24])
    recv_ip = struct.unpack('BBBB', raw_data[24:28])

    if op_code == 2:

        src_ip = str(send_ip).replace('(', '').replace(')', '').replace(',', '.').replace(' ', '')
        src = []
        for i in sender_mac:
            val = hex(i)
            val = val.replace('0x', '').zfill(2)
            src.append(val)
        src = ':'.join(src)
        pro.info = src_ip + ' is at ' + src
        pro.info += ' (Reply)'
    elif op_code == 1:
        src_ip = str(send_ip).replace('(', '').replace(')', '').replace(',', '.').replace(' ', '')
        des_ip = str(recv_ip).replace('(', '').replace(')', '').replace(',', '.').replace(' ', '')
        pro.info = 'Who has ' + des_ip + ' ? Tell ' + src_ip
    return True


def handle_ip(raw_data, pro: Protocol):
    # version = (raw_data[0] & 0xf0) >> 4
    header_len = raw_data[0] & 0x0f
    # print('version:', version, 'header_len', header_len * 4, 'Byte')
    if header_len == 5:
        # TOS = raw_data[1]
        total_len = ntohs(struct.unpack('H', raw_data[2:4])[0])
        pro.ip_payload_len = total_len - header_len * 4
        # identification = ntohs(struct.unpack('H', raw_data[4:6])[0])
        # identification = f'0x{identification:02x}'
        # flag = raw_data[6]
        # fragment_offset = raw_data[7]
        # time_to_live = raw_data[8]
        protocol = raw_data[9]
        # checksum = ntohs(struct.unpack('H', raw_data[10:12])[0])
        # checksum = f'0x{checksum:04x}'
        src = struct.unpack('BBBB', raw_data[12:16])
        des = struct.unpack('BBBB', raw_data[16:20])
        pro.src_ip = str(src).replace('(', '').replace(')', '').replace(',', '.').replace(' ', '')
        pro.des_ip = str(des).replace('(', '').replace(')', '').replace(',', '.').replace(' ', '')
        return protocol, header_len * 4
    else:
        return 0, 0


def handle_tcp(raw_data, pro: Protocol):
    if len(raw_data) >= 20:
        src = ntohs(struct.unpack('H', raw_data[0:2])[0])
        # print('src port', src, end=' ')
        des = ntohs(struct.unpack('H', raw_data[2:4])[0])
        # print('des port', des)
        pro.src_port = str(src)
        pro.des_port = str(des)
        pro.info = str(src) + ' -> ' + str(des)
        seq_number = ntohl(struct.unpack('I', raw_data[4:8])[0])
        # print('seq', seq_number, end=' ')
        ack_number = ntohl(struct.unpack('I', raw_data[8:12])[0])
        pro.seq = seq_number
        pro.info += ' seq:' + str(seq_number) + ' ack:' + str(ack_number)
        # print('ack', ack_number)
        tcp_header_len = (raw_data[12] & 0xf0) >> 4
        # print('Header length', 4 * tcp_header_len)
        flag = ntohs(struct.unpack('H', raw_data[12:14])[0])
        content = []
        if flag & 2 == 2:
            content.append('SYN')
        if flag & 32 == 32:
            content.append('Urg')
        if flag & 16 == 16:
            content.append('ACK')
        if flag & 8 == 8:
            content.append('PSH')
        if flag & 1 == 1:
            content.append('FIN')
        if flag & 4 == 4:
            content.append('Rst')
        if content:
            pro.info += '[' + ','.join(content) + ']'
        # print('flag', f'0x{flag & 0x0fff:03x}', sp.handle_tcp_flag(flag))
        # window = ntohs(struct.unpack('H', raw_data[14:16])[0])
        # print('window', window)
        # checksum = ntohs(struct.unpack('H', raw_data[16:18])[0])
        # print('checksum', f'0x{checksum:04x}')
        # urgent_pointer = ntohs(struct.unpack('H', raw_data[18:20])[0])
        # print('Urgent Pointer', urgent_pointer)
        pro.tcp_header = tcp_header_len * 4
        pro.payload_len = pro.len - (14 + 20 + pro.tcp_header)
        pro.segment = pro.len - (14 + 20 + pro.tcp_header)
        pro.assemble_payload_len = pro.len - (14 + 20 + pro.tcp_header)
        return tcp_header_len * 4
    else:
        return 0


def handle_udp(raw_data, pro: Protocol):
    src = ntohs(struct.unpack('H', raw_data[0:2])[0])
    # print('src port', src)
    pro.src_port = str(src)
    des = ntohs(struct.unpack('H', raw_data[2:4])[0])
    pro.des_port = str(des)
    if des == 53 or src == 53:
        pro.protocol = 'UDP(DNS)'
        if handle_dns(raw_data[8:], pro):
            return True
    pro.info = str(src) + ' -> ' + str(des)
    # print('des port', des)
    # length = ntohs(struct.unpack('H', raw_data[4:6])[0])
    # print('length', length)
    # checksum = ntohs(struct.unpack('H', raw_data[6:8])[0])
    # print('checksum', checksum)
    return True


def handle_dns(raw_data, pro: Protocol):
    if len(raw_data) >= 12:
        transaction_id = ntohs(struct.unpack('H', raw_data[0:2])[0])
        transaction_id = '0x' + hex(transaction_id).replace('0x', '').zfill(4)
        flags = ntohs(struct.unpack('H', raw_data[2:4])[0])
        if flags & 0x8000 == 0x8000:
            QR = 'Standard query response '
        else:
            QR = 'Standard query '
        name, length = analysis_dns_name(raw_data[12:])
        if name:
            pro.info = QR + transaction_id + ' ' + name
            return True
        else:
            pro.protocol = 'UDP'
            return False
    else:
        pro.protocol = 'UDP'
        return False


def handle_tls(raw_data, pro: Protocol):
    if len(raw_data) < 5:
        return False
    else:
        content_type = raw_data[0]
        if 20 <= content_type <= 23:
            version = ntohs(struct.unpack('H', raw_data[1:3])[0])
            ver = tls_version(version)
            pro.protocol = 'TCP(' + ver + ')'
            length = ntohs(struct.unpack('H', raw_data[3:5])[0])
            if len(raw_data) >= length:
                sub_type = tls_hand_shake_type(raw_data[5])
                pro.info = sub_type + '   '
            return length + 5
        else:
            return False


def handle_sub_tls(raw_data, pro: Protocol):
    if len(raw_data) < 5:
        return False
    else:
        content_type = raw_data[0]
        # version = ntohs(struct.unpack('H', raw_data[1:3])[0])
        length = ntohs(struct.unpack('H', raw_data[3:5])[0])
        if len(raw_data) >= length:
            if content_type == 22:
                content_type = raw_data[5]
                pro.info += tls_hand_shake_type(content_type) + '   '
            else:
                pro.info += tls_type(content_type) + '   '
            return length + 5
        return False


def tls_version(val):
    if val == 0x0300:
        return 'SSL 3.0'
    elif val == 0x0301:
        return 'TLS 1.0'
    elif val == 0x0302:
        return 'TLS 1.1'
    elif val == 0x0303:
        return 'TLS 1.2'
    elif val == 0x0304:
        return 'TLS 1.3'
    else:
        return 'TLS'


def tls_hand_shake_type(val):
    if val == 1:
        return "Client Hello"
    elif val == 2:
        return "Server hello"
    elif val == 11:
        return "Certificate"
    elif val == 16:
        return "Client Key Exchange"
    elif val == 4:
        return "New Session Ticket"
    elif val == 12:
        return "Server Key Exchange"
    elif val == 14:
        return "Server Hello Done"
    elif val == 20:
        return "Change Cipher Spec"
    else:
        return 'Encrypted message'


def tls_type(val):
    if val == 20:
        return 'Change Cipher Spec'
    elif val == 21:
        return 'Alert'
    elif val == 22:
        return 'Handshake'
    elif val == 23:
        return 'Application Data'
    else:
        return ''


def isOICQ(raw_data, pro: Protocol):
    if raw_data and raw_data[0] == 0x02:
        pro.protocol = 'UDP(OICQ)'
    else:
        return


def analysis_dns_name(raw_data):
    if not len(raw_data):
        return '', 0
    i = 0
    res = []
    while raw_data[i]:
        if 0 < raw_data[i] <= 63:
            pre_len = raw_data[i]
            tmp = ''
            for it in range(1, pre_len + 1):
                tmp += chr(raw_data[i + it])
            i = i + pre_len + 1
            res.append(tmp)
        else:
            return res, i + 1
    res = '.'.join(res)
    return res, i + 1
