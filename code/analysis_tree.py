import re
import struct
from socket import ntohs, ntohl

from analysis_protocol import Protocol
from handle_certificate import analysis_certification_dire


def analysis_ethernet(pro: Protocol):
    dst = 'Destination:' + pro.des_mac
    src = 'Source:' + pro.src_mac
    ty = ntohs(struct.unpack('H', pro.data[12:14])[0])
    if ty == 0x0800:
        type = 'Type:IPv4 (0x0800)'
    elif ty == 0x0806:
        type = 'Type:Arp (0x0806)'
    else:
        type = 'Type: Unknown (' + str(hex(ty)) + ')'
    return dst, src, type


def analysis_arp(pro: Protocol):
    raw_data = pro.data[14:]
    ty = ntohs(struct.unpack('H', pro.data[12:14])[0])
    if ty == 0x0806:
        hardware_type = ntohs(struct.unpack('H', raw_data[0:2])[0])
        if hardware_type == 1:
            hardware_type = 'Hardware type: Ethernet (1)'
        else:
            hardware_type = 'Hardware type: (' + str(hardware_type) + ')'
        protocol_type = ntohs(struct.unpack('H', raw_data[2:4])[0])
        if protocol_type == 0x0800:
            protocol_type = 'Protocol type: IPv4 (0x0800)'
        else:
            protocol_type = 'Protocol type: (' + hex(protocol_type) + ')'
        harware_size = raw_data[4]
        harware_size = 'Hardware size: ' + str(harware_size)
        protocol_size = raw_data[5]
        protocol_size = 'Protocol size: ' + str(protocol_size)
        op_code = ntohs(struct.unpack('H', raw_data[6:8])[0])
        if op_code == 1:
            op_code = 'Opcode: request (1)'
        elif op_code == 2:
            op_code = 'Opcode: reply (2)'
        sender_mac = struct.unpack('BBBBBB', raw_data[8:14])
        src = []
        for i in sender_mac:
            val = hex(i)
            val = val.replace('0x', '').zfill(2)
            src.append(val)
        src = ':'.join(src)
        src = 'Sender MAC address: ' + src
        send_ip = struct.unpack('BBBB', raw_data[14:18])
        send_ip = str(send_ip).replace('(', '').replace(')', '').replace(',', '.').replace(' ', '')
        send_ip = 'Sender IP address: ' + send_ip
        recv_mac = struct.unpack('BBBBBB', raw_data[18:24])
        des = []
        for i in recv_mac:
            val = hex(i)
            val = val.replace('0x', '').zfill(2)
            des.append(val)
        des = ':'.join(des)
        des = 'Target MAC address: ' + des
        recv_ip = struct.unpack('BBBB', raw_data[24:28])
        recv_ip = str(recv_ip).replace('(', '').replace(')', '').replace(',', '.').replace(' ', '')
        recv_ip = 'Target IP address: ' + recv_ip
        return hardware_type, protocol_type, harware_size, \
               protocol_size, op_code, src, send_ip, des, recv_ip
    else:
        return 0, 0, 0, 0, 0, 0, 0, 0, 0


def analysis_ipv4(pro: Protocol):
    raw_data = pro.data[14:]
    version = bin((raw_data[0] & 0xf0) >> 4).replace('0b', '0') + ' .... = Version:' + str((raw_data[0] & 0xf0) >> 4)
    raw_len = raw_data[0] & 0x0f
    header_len = '.... ' + bin(raw_len).replace('0b', '0') + ' = Header Length:' \
                 + str(raw_len * 4) + ' bytes (' + str(raw_len) + ')'
    if raw_len == 5:
        TOS = 'Differentiated Services Field: ' + str(raw_data[1])
        total_len = 'Total Length:' + str(ntohs(struct.unpack('H', raw_data[2:4])[0]))
        identification = ntohs(struct.unpack('H', raw_data[4:6])[0])
        identification = 'Identification: ' + f'0x{identification:04x}'
        flag = raw_data[6]
        res_flag = []
        add_flag = ''
        if flag & 128 == 128:
            res_flag.append('1... .... = Reserved bit: Set')
            add_flag = 'Reserved'
        else:
            res_flag.append('0... .... = Reserved bit: Not Set')
        if flag & 64 == 64:
            res_flag.append('.1.. .... = Don\'t Fragment: Set')
            add_flag = 'Don\'t Fragment'
        else:
            res_flag.append('.0.. .... = Don\'t Fragment: Not Set')
        if flag & 32 == 32:
            res_flag.append('..1. .... = More Fragment: Set')
            add_flag = 'More Fragment'
        else:
            res_flag.append('..0. .... = More Fragment: Not Set')
        flag = 'Flags: ' + hex(flag) + ',' + add_flag
        fragment_offset = raw_data[7]
        content = '...' + bin(fragment_offset & 0x1fff).replace('0b', '').zfill(13) + ' = Fragment Offset: ' + str(
            fragment_offset & 0x1fff)

        time_to_live = 'Time to Live: ' + str(raw_data[8])
        protocol = raw_data[9]
        if protocol == 6:
            protocol = 'TCP (' + str(protocol) + ')'
        elif protocol == 17:
            protocol = 'UDP (' + str(protocol) + ')'
        elif protocol == 1:
            protocol = 'ICMP (' + str(protocol) + ')'
        else:
            protocol = 'Unknown (' + str(protocol) + ')'
        checksum = ntohs(struct.unpack('H', raw_data[10:12])[0])
        checksum = f'0x{checksum:04x}'
        checksum = 'Header Checksum: ' + checksum
        src = struct.unpack('BBBB', raw_data[12:16])
        des = struct.unpack('BBBB', raw_data[16:20])
        pro.src_ip = str(src).replace('(', '').replace(')', '').replace(',', '.').replace(' ', '')
        pro.des_ip = str(des).replace('(', '').replace(')', '').replace(',', '.').replace(' ', '')
        src = 'Source Address: ' + pro.src_ip
        des = 'Destination Address: ' + pro.des_ip
        return version, header_len, TOS, total_len, identification, flag, res_flag, content, time_to_live, \
               protocol, checksum, src, des
    else:
        return 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0


def analysis_tcp(pro: Protocol):
    raw_data = pro.data[14 + 20:]
    if len(raw_data) >= 20:
        src = ntohs(struct.unpack('H', raw_data[0:2])[0])
        pro.src_port = str(src)
        des = ntohs(struct.unpack('H', raw_data[2:4])[0])
        pro.des_port = str(des)
        pro.info = str(src) + ' -> ' + str(des)

        src = 'Source Port: ' + str(src)
        des = 'Destination Port: ' + str(des)

        seq_number = ntohl(struct.unpack('I', raw_data[4:8])[0])

        ack_number = ntohl(struct.unpack('I', raw_data[8:12])[0])
        pro.info += ' seq:' + str(seq_number) + ' ack:' + str(ack_number)

        seq_number = 'Sequence Number (raw): ' + str(seq_number)
        ack_number = 'Acknowledgment Number (raw): ' + str(ack_number)
        tcp_header_len = (raw_data[12] & 0xf0) >> 4
        raw_len = tcp_header_len * 4
        tcp_header_len = bin(tcp_header_len).replace('0b', '0') + ' .... = Header Length: ' \
                         + str(tcp_header_len * 4) + ' byte (' + str(tcp_header_len) + ')'
        flag = ntohs(struct.unpack('H', raw_data[12:14])[0])
        content = []
        ret_flag = []
        if flag & 3584 == 3584:
            ret_flag.append('111. .... .... = Reserved: Set')
        else:
            ret_flag.append('000. .... .... = Reserved: Not Set')

        if flag & 256 == 256:
            ret_flag.append('...1 .... .... = Nonce: Set')
        else:
            ret_flag.append('...0 .... .... = Nonce: Not Set')

        if flag & 128 == 128:
            ret_flag.append('.... 1... .... = Congestion Window Reduced (CWR): Set')
        else:
            ret_flag.append('.... 0... .... = Congestion Window Reduced (CWR): Not Set')
        if flag & 64 == 64:
            ret_flag.append('.... .1.. .... = ECN-Echo: Set')
        else:
            ret_flag.append('.... .0.. .... = ECN-Echo: Not Set')

        if flag & 32 == 32:
            content.append('Urg')
            ret_flag.append('.... ..1. .... = Urgent: Set')
        else:
            ret_flag.append('.... ..0. .... = Urgent: Not Set')
        if flag & 16 == 16:
            content.append('ACK')
            ret_flag.append('.... ...1 .... = Acknowledgment: Set')
        else:
            ret_flag.append('.... ...0 .... = Acknowledgment: Not Set')
        if flag & 8 == 8:
            content.append('PSH')
            ret_flag.append('.... .... 1... = Push: Set')
        else:
            ret_flag.append('.... .... 0... = Push: Not Set')
        if flag & 4 == 4:
            content.append('Rst')
            ret_flag.append('.... .... .1.. = Reset: Set')
        else:
            ret_flag.append('.... .... .0.. = Reset: Not Set')
        if flag & 2 == 2:
            content.append('SYN')
            ret_flag.append('.... .... ..1. = Syn: Set')
        else:
            ret_flag.append('.... .... ..0. = Syn: Not Set')
        if flag & 1 == 1:
            content.append('FIN')
            ret_flag.append('.... .... ...1 = Fin: Set')
        else:
            ret_flag.append('.... .... ...0 = Fin: Not Set')

        if content:
            pro.info += '[' + ','.join(content) + ']'
        flag = 'Flags: ' + hex(flag).zfill(3) + '(' + ','.join(content) + ')'
        window = ntohs(struct.unpack('H', raw_data[14:16])[0])
        window = 'Window: ' + str(window)
        checksum = ntohs(struct.unpack('H', raw_data[16:18])[0])
        checksum = 'Checksum: ' + f'0x{checksum:04x}'
        urgent_pointer = ntohs(struct.unpack('H', raw_data[18:20])[0])
        urgent_pointer = 'Urgent Pointer: ' + str(urgent_pointer)
        has_option = False
        if raw_len == 32:
            has_option = True
        return src, des, seq_number, ack_number, tcp_header_len, flag, ret_flag, window, \
               checksum, urgent_pointer, has_option
    else:
        return 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0


def analysis_udp(pro: Protocol):
    raw_data = pro.data[14 + 20:]
    if len(raw_data) >= 8:
        src = ntohs(struct.unpack('H', raw_data[0:2])[0])
        src = 'Source Port: ' + str(src)
        des = ntohs(struct.unpack('H', raw_data[2:4])[0])
        des = 'Destination Port: ' + str(des)
        length = ntohs(struct.unpack('H', raw_data[4:6])[0])
        payload_len = length
        length = 'Length: ' + str(length)
        checksum = ntohs(struct.unpack('H', raw_data[6:8])[0])
        checksum = 'Checksum: ' + hex(checksum)
        payload = 'UDP payload (' + str(payload_len - 8) + ')'
        return src, des, length, checksum, payload
    else:
        return 0, 0, 0, 0, 0


def analysis_dns(pro: Protocol):
    raw_data = pro.data[14 + 20 + 8:]
    if len(raw_data) >= 12:
        transaction_id = ntohs(struct.unpack('H', raw_data[0:2])[0])
        transaction_id = 'Transaction ID: ' + hex(transaction_id).zfill(4)
        flags = ntohs(struct.unpack('H', raw_data[2:4])[0])
        if flags & 0x8000 == 0x8000:
            QR = '1... .... .... .... = Response: Message is a response'
        else:
            QR = '0... .... .... .... = Response: Message is a query'
        Opcode = analysis_op_code((flags & 0x7800) >> 11)
        Opcode = '.000 0... .... .... = Opcode: ' + Opcode
        if flags & 0x0400 == 0x0400:
            AA = '.... .1.. .... .... = Authoritative: Server is an authority for domain'
        else:
            AA = '.... .0.. .... .... = Authoritative: Server is not an authority for domain'
        if flags & 0x0200 == 0x0200:
            TC = '.... ..1. .... .... = Truncated: Message is truncated'
        else:
            TC = '.... ..0. .... .... = Truncated: Message is not truncated'
        if flags & 0x0100 == 0x0100:
            RD = '.... ...1 .... .... = Recursion desired: Do query recursively'
        else:
            RD = '.... ...0 .... .... = Recursion desired: Do not query recursively'
        if flags & 0x0080 == 0x0080:
            RA = '.... .... 1... .... = Recursion available: Server can do recursive queries'
        else:
            RA = '.... .... 0... .... = Recursion available: Server can not do recursive queries'
        Z = '.... .... .0.. .... = Z: reserved (0)'
        if flags & 0x000f == 0:
            rcode = '.... .... .... 0000 = Reply code: No error (0)'
        else:
            rcode = '.... .... ....' + hex(flags & 0x000f).replace('0x', '').zfill(4) \
                    + ' = Reply code: No error (' + str(flags & 0x000f) + ')'
        flags = 'Flags: 0x' + hex(flags).replace('0x', '').zfill(4)
        Question = ntohs(struct.unpack('H', raw_data[4:6])[0])
        Answer = ntohs(struct.unpack('H', raw_data[6:8])[0])
        Authority = ntohs(struct.unpack('H', raw_data[8:10])[0])
        Additional = ntohs(struct.unpack('H', raw_data[10:12])[0])
        i = 0
        count = 0
        question_res = []
        while i < Question:
            name, length = analysis_dns_name(raw_data[12 + count:])
            query_name = 'Name: ' + name
            name_length = len(name)
            name_length = '[Name Length: ' + str(name_length) + ']'
            type = ntohs(struct.unpack('H', raw_data[12 + length: 12 + length + 2])[0])
            type = 'Type: ' + analysis_dns_type(type)
            Class = ntohs(struct.unpack('H', raw_data[12 + length + 2: 12 + length + 4])[0])
            Class = 'Class: IN (0x' + hex(Class).replace('0x', '').zfill(4) + ')'
            i += 1
            count += length + 4
            question_res.append((query_name, name_length, type, Class))

        Question = 'Questions: ' + str(Question)
        Answer = 'Answer RRs: ' + str(Answer)
        Authority = 'Authority RRs: ' + str(Authority)
        Additional = 'Additional RRs: ' + str(Additional)
        return transaction_id, flags, QR, Opcode, AA, TC, RD, RA, Z, rcode, \
               Question, Answer, Authority, Additional, question_res
    else:
        return 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0


def analysis_op_code(op_code):
    if op_code == 0:
        return 'Standard query (0)'
    elif op_code == 1:
        return 'Reverse query (1)'
    elif op_code == 2:
        return 'Server status request (2)'
    else:
        return 'Reserved'


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


def analysis_dns_type(type):
    if type == 1:
        return 'A (IPv4) (1)'
    elif type == 2:
        return 'NS (Name Server) (2)'
    elif type == 5:
        return 'CNAME (5)'
    elif type == 6:
        return 'SOA (6)'
    elif type == 11:
        return 'WKS (11)'
    elif type == 12:
        return 'PTR (12)'
    elif type == 13:
        return 'HINFO (13)'
    elif type == 15:
        return 'MX (15)'
    elif type == 28:
        return 'AAAA (IPv6) (28)'
    elif type == 252:
        return 'AXFR (252)'
    elif type == 255:
        return 'ANY (255)'
    else:
        return 'Unknown (' + str(type) + ')'


def analysis_tls(data, offset):
    raw_data = data[offset:]
    if len(raw_data) <= 0:
        return 0, 0, 0, 0, 0, 0, 0
    content_type = raw_data[0]
    if 20 <= content_type <= 23:
        con_type = tls_type(content_type)
        content_type = 'Content Type: ' + con_type + '(' + str(content_type) + ")"
        version = ntohs(struct.unpack('H', raw_data[1:3])[0])
        ver = tls_version(version)
        version = f'0x{version:04x}'
        version = ver + '(' + version + ')'
        length = ntohs(struct.unpack('H', raw_data[3:5])[0])
        if not len(raw_data) >= length:
            return 0, 0, 0, 0, 0, 0, length + 5
        raw_length = length + 5
        length = 'Length: ' + str(length)
        byte_array = ''
        if raw_data[0] in [21, 23]:
            for it in raw_data[5:]:
                byte_array += str(it)
            enc = 'Encrypted Application Data: ' + byte_array
        else:
            enc = ''
        return content_type, con_type, version, ver, length, enc, raw_length
    else:
        return 0, 0, 0, 0, 0, 0, 0


def analysis_tls_list(data, offset):
    res = []
    raw_data = data[offset:]
    content_type, con_type, version, \
    ver, length, enc, raw_length = analysis_tls(data, offset)
    if content_type and con_type:
        res.append((content_type, con_type, version, ver, length, enc, raw_length))
    total_len = raw_length
    flag = len(raw_data) - raw_length
    while flag > 0:
        content_type, con_type, version, \
        ver, length, enc, raw_length = analysis_tls(data, offset + total_len)
        if raw_length:
            flag -= raw_length
            total_len += raw_length
            res.append((content_type, con_type, version, ver, length, enc, raw_length))
        else:
            break
    return res


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
        return ''


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
    else:
        return ''


def tls_cipher_suite(val):
    if val == 0x00ff:
        return "TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0x00ff)"
    elif val == 0xc02c:
        return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xc02c)"
    elif val == 0xc030:
        return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)"
    elif val == 0x009f:
        return "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 (0x009f)"
    elif val == 0xc0ad:
        return "TLS_ECDHE_ECDSA_WITH_AES_256_CCM (0xc0ad)"
    elif val == 0xc09f:
        return "TLS_DHE_RSA_WITH_AES_256_CCM (0xc09f)"
    elif val == 0xc024:
        return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 (0xc024)"
    elif val == 0xc028:
        return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 (0xc028)"
    elif val == 0x006b:
        return "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 (0x006b)"
    elif val == 0xc00a:
        return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0xc00a)"
    elif val == 0xc014:
        return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014)"
    elif val == 0x0039:
        return "TLS_DHE_RSA_WITH_AES_256_CBC_SHA (0x0039)"
    elif val == 0xc0af:
        return "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 (0xc0af)"
    elif val == 0xc0a3:
        return "TLS_DHE_RSA_WITH_AES_256_CCM_8 (0xc0a3)"
    elif val == 0xc087:
        return "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 (0xc087)"
    elif val == 0xc08b:
        return "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 (0xc08b)"
    elif val == 0xc07d:
        return "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 (0xc07d)"
    elif val == 0xc073:
        return "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 (0xc073)"
    elif val == 0xc077:
        return "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 (0xc077)"
    elif val == 0x00c4:
        return "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 (0x00c4)"
    elif val == 0x0088:
        return "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA (0x0088)"
    elif val == 0xc02b:
        return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b)"
    elif val == 0xc02f:
        return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)"
    elif val == 0x009e:
        return "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 (0x009e)"
    elif val == 0xc0ac:
        return "TLS_ECDHE_ECDSA_WITH_AES_128_CCM (0xc0ac)"
    elif val == 0xc09e:
        return "TLS_DHE_RSA_WITH_AES_128_CCM (0xc09e)"
    elif val == 0xc023:
        return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 (0xc023)"
    elif val == 0xc027:
        return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (0xc027)"
    elif val == 0x0067:
        return "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 (0x0067)"
    elif val == 0xc009:
        return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0xc009)"
    elif val == 0xc013:
        return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013)"
    elif val == 0x0033:
        return "TLS_DHE_RSA_WITH_AES_128_CBC_SHA (0x0033)"
    elif val == 0xc0ae:
        return "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 (0xc0ae)"
    elif val == 0xc0a2:
        return "TLS_DHE_RSA_WITH_AES_128_CCM_8 (0xc0a2)"
    elif val == 0xc086:
        return "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 (0xc086)"
    elif val == 0xc08a:
        return "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 (0xc08a)"
    elif val == 0xc07c:
        return "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 (0xc07c)"
    elif val == 0xc072:
        return "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 (0xc072)"
    elif val == 0xc076:
        return "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 (0xc076)"
    elif val == 0x00be:
        return "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 (0x00be)"
    elif val == 0x0045:
        return "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA (0x0045)"
    elif val == 0xc008:
        return "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA (0xc008)"
    elif val == 0xc012:
        return "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA (0xc012)"
    elif val == 0x0016:
        return "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA (0x0016)"
    elif val == 0x00ab:
        return "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 (0x00ab)"
    elif val == 0xc0a7:
        return "TLS_DHE_PSK_WITH_AES_256_CCM (0xc0a7)"
    elif val == 0xc038:
        return "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 (0xc038)"
    elif val == 0x00b3:
        return "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 (0x00b3)"
    elif val == 0xc036:
        return "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA (0xc036) "
    elif val == 0x0091:
        return "TLS_DHE_PSK_WITH_AES_256_CBC_SHA (0x0091)"
    elif val == 0xc091:
        return "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 (0xc091)"
    elif val == 0xc09b:
        return "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 (0xc09b)"
    elif val == 0xc097:
        return "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 (0xc097)"
    elif val == 0xc0ab:
        return "TLS_PSK_DHE_WITH_AES_256_CCM_8 (0xc0ab)"
    elif val == 0x00aa:
        return "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 (0x00aa)"
    elif val == 0xc0a6:
        return "TLS_DHE_PSK_WITH_AES_128_CCM (0xc0a6)"
    elif val == 0xc037:
        return "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 (0xc037)"
    elif val == 0x00b2:
        return "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 (0x00b2)"
    elif val == 0xc035:
        return "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA (0xc035)"
    elif val == 0x0090:
        return "TLS_DHE_PSK_WITH_AES_128_CBC_SHA (0x0090)"
    elif val == 0xc090:
        return "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 (0xc090)"
    elif val == 0xc096:
        return "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 (0xc096)"
    elif val == 0xc09a:
        return "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 (0xc09a)"
    elif val == 0xc0aa:
        return "TLS_PSK_DHE_WITH_AES_128_CCM_8 (0xc0aa)"
    elif val == 0xc034:
        return "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA (0xc034)"
    elif val == 0x008f:
        return "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA (0x008f)"
    elif val == 0x009d:
        return "TLS_RSA_WITH_AES_256_GCM_SHA384 (0x009d)"
    elif val == 0xc09d:
        return "TLS_RSA_WITH_AES_256_CCM (0xc09d)"
    elif val == 0x003d:
        return "TLS_RSA_WITH_AES_256_CBC_SHA256 (0x003d)"
    elif val == 0x0035:
        return "TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)"
    elif val == 0xc032:
        return "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 (0xc032)"
    elif val == 0xc02a:
        return "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 (0xc02a)"
    elif val == 0xc00f:
        return "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA (0xc00f)"
    elif val == 0xc02e:
        return "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 (0xc02e)"
    elif val == 0xc026:
        return "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 (0xc026)"
    elif val == 0xc005:
        return "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA (0xc005)"
    elif val == 0xc0a1:
        return "TLS_RSA_WITH_AES_256_CCM_8 (0xc0a1)"
    elif val == 0xc07b:
        return "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 (0xc07b)"
    elif val == 0x00c0:
        return "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 (0x00c0)"
    elif val == 0x0084:
        return "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA (0x0084)"
    elif val == 0xc08d:
        return "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 (0xc08d)  "
    elif val == 0xc079:
        return "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 (0xc079)  "
    elif val == 0xc089:
        return "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 (0xc089)"
    elif val == 0xc075:
        return "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 (0xc075)"
    elif val == 0x009c:
        return "TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009c)"
    elif val == 0xc09c:
        return "TLS_RSA_WITH_AES_128_CCM (0xc09c)"
    elif val == 0x003c:
        return "TLS_RSA_WITH_AES_128_CBC_SHA256 (0x003c)"
    elif val == 0x002f:
        return "TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)"
    elif val == 0xc031:
        return "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 (0xc031)"
    elif val == 0xc029:
        return "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 (0xc029)"
    elif val == 0xc00e:
        return "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA (0xc00e)"
    elif val == 0xc02d:
        return "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02d)"
    elif val == 0xc025:
        return "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 (0xc025)"
    elif val == 0xc004:
        return "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA (0xc004)"
    elif val == 0xc0a0:
        return "TLS_RSA_WITH_AES_128_CCM_8 (0xc0a0)"
    elif val == 0xc07a:
        return "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 (0xc07a)"
    elif val == 0x00ba:
        return "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 (0x00ba)"
    elif val == 0x0041:
        return "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA (0x0041)"
    elif val == 0xc08c:
        return "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 (0xc08c)"
    elif val == 0xc078:
        return "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 (0xc078)"
    elif val == 0xc088:
        return "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 (0xc088)"
    elif val == 0xc074:
        return "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 (0xc074)"
    elif val == 0x000a:
        return "TLS_RSA_WITH_3DES_EDE_CBC_SHA (0x000a)"
    elif val == 0xc00d:
        return "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA (0xc00d)  "
    elif val == 0xc003:
        return "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA (0xc003)"
    elif val == 0x00ad:
        return "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 (0x00ad)"
    elif val == 0x00b7:
        return "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 (0x00b7)"
    elif val == 0x0095:
        return "TLS_RSA_PSK_WITH_AES_256_CBC_SHA (0x0095)"
    elif val == 0xc093:
        return "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 (0xc093)"
    elif val == 0xc099:
        return "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 (0xc099)"
    elif val == 0x00ac:
        return "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 (0x00ac)"
    elif val == 0x00b6:
        return "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 (0x00b6)"
    elif val == 0x0094:
        return "TLS_RSA_PSK_WITH_AES_128_CBC_SHA (0x0094)"
    elif val == 0xc092:
        return "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 (0xc092)"
    elif val == 0xc098:
        return "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 (0xc098)"
    elif val == 0x0093:
        return "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA (0x0093)"
    elif val == 0x00a9:
        return "TLS_PSK_WITH_AES_256_GCM_SHA384 (0x00a9)"
    elif val == 0xc0a5:
        return "TLS_PSK_WITH_AES_256_CCM (0xc0a5)"
    elif val == 0x00af:
        return "TLS_PSK_WITH_AES_256_CBC_SHA384 (0x00af)"
    elif val == 0x008d:
        return "TLS_PSK_WITH_AES_256_CBC_SHA (0x008d)"
    elif val == 0xc08f:
        return "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 (0xc08f)"
    elif val == 0xc095:
        return "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 (0xc095)"
    elif val == 0xc0a9:
        return "TLS_PSK_WITH_AES_256_CCM_8 (0xc0a9)"
    elif val == 0x00a8:
        return "TLS_PSK_WITH_AES_128_GCM_SHA256 (0x00a8)"
    elif val == 0xc0a4:
        return "TLS_PSK_WITH_AES_128_CCM (0xc0a4)"
    elif val == 0x00ae:
        return "TLS_PSK_WITH_AES_128_CBC_SHA256 (0x00ae)"
    elif val == 0x008c:
        return "TLS_PSK_WITH_AES_128_CBC_SHA (0x008c)"
    elif val == 0xc08e:
        return "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 (0xc08e)"
    elif val == 0xc094:
        return "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 (0xc094)"
    elif val == 0xc0a8:
        return "TLS_PSK_WITH_AES_128_CCM_8 (0xc0a8)"
    elif val == 0x008b:
        return "TLS_PSK_WITH_3DES_EDE_CBC_SHA (0x008b)"
    elif val == 0xc007:
        return "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA (0xc007)"
    elif val == 0xc011:
        return "TLS_ECDHE_RSA_WITH_RC4_128_SHA (0xc011)"
    elif val == 0xc033:
        return "TLS_ECDHE_PSK_WITH_RC4_128_SHA (0xc033)"
    elif val == 0x008e:
        return "TLS_DHE_PSK_WITH_RC4_128_SHA (0x008e) "
    elif val == 0x0005:
        return "TLS_RSA_WITH_RC4_128_SHA (0x0005)"
    elif val == 0x0004:
        return "TLS_RSA_WITH_RC4_128_MD5 (0x0004)"
    elif val == 0xc00c:
        return "TLS_ECDH_RSA_WITH_RC4_128_SHA (0xc00c)"
    elif val == 0xc002:
        return "TLS_ECDH_ECDSA_WITH_RC4_128_SHA (0xc002) "
    elif val == 0x0092:
        return "TLS_RSA_PSK_WITH_RC4_128_SHA (0x0092)"
    elif val == 0x008a:
        return "TLS_PSK_WITH_RC4_128_SHA (0x008a)"
    elif val == 0x1302:
        return "TLS_AES_256_GCM_SHA384 (0x1302)"
    elif val == 0x1303:
        return "TLS_CHACHA20_POLY1305_SHA256 (0x1303)"
    elif val == 0x1301:
        return "TLS_AES_128_GCM_SHA256 (0x1301)"
    elif val == 0xcca9:
        return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca9)"
    elif val == 0xcca8:
        return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca8)"
    elif val == 0xccaa:
        return "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xccaa)"
    elif val == 0xfafa:
        return "Reserved (GREASE) (0xfafa)"
    else:
        return hex(val)


def tls_handshak_extension(val):
    if val == 0:
        return "server_name"
    elif val == 5:
        return "status_request"
    elif val == 11:
        return "ec_point_format"
    elif val == 10:
        return "supported_groups"
    elif val == 35:
        return "session_ticket"
    elif val == 22:
        return "encrypt_then_mac"
    elif val == 23:
        return "extended_master_secret"
    elif val == 13:
        return "signature_algorithms"
    elif val == 43:
        return "supported_versions"
    elif val == 45:
        return "psk_key_exchange_modes"
    elif val == 51:
        return "key_share"
    elif val == 21:
        return "padding"
    elif val == 18:
        return "signed_certificate_timestamp"
    elif val == 39578:
        return "Reserved (GREASE) (39578)"
    else:
        return "Unknown type"


def tls_externsion_support_group(val):
    if val == 0x001d:
        return "x25519 (0x001d)"
    elif val == 0x0017:
        return "secp256r1 (0x0017)"
    elif val == 0x001e:
        return "x448 (0x001e)"
    elif val == 0x0019:
        return "secp521r1 (0x0019)"
    elif val == 0x0018:
        return "secp384r1 (0x0018)"
    elif val == 0x001c:
        return "brainpoolP512r1 (0x001c)"
    elif val == 0x001b:
        return "brainpoolP384r1 (0x001b)"
    elif val == 0x0016:
        return "secp256k1 (0x0016)"
    elif val == 0x001a:
        return "brainpoolP256r1 (0x001a)"
    elif val == 0x0015:
        return "secp224r1 (0x0015)"
    elif val == 0x0014:
        return "secp224k1 (0x0014)"
    elif val == 0x0013:
        return "secp192r1 (0x0013)"
    elif val == 0x0012:
        return "secp192k1 (0x0012)"
    else:
        return hex(val)


def tls_extension_ECPointFormat(val):
    if val == 0:
        return "EC point format: uncompressed (0)"
    elif val == 1:
        return "EC point format: ansiX962_compressed_prime (1)"
    elif val == 2:
        return "EC point format: ansiX962_compressed_char2 (2)"
    else:
        return hex(val)


def tls_extension_hash(val):
    if val == 4:
        return "SHA256"
    elif val == 5:
        return "SHA384"
    elif val == 6:
        return "SHA512"
    elif val == 2:
        return "SHA1"
    elif val == 3:
        return "SHA224"
    elif val == 1:
        return "MD5"
    else:
        return "Unknown"


def tls_extension_signature(val):
    if val == 1:
        return "RSA"
    elif val == 2:
        return "DSA"
    elif val == 3:
        return "ECDSA"
    else:
        return "Unknown"


def tls_hand_shake(data, offset):
    raw_data = data[offset:]
    if raw_data[0] == 1 and len(raw_data) >= 44:
        hand_shake_type = tls_hand_shake_type(raw_data[0])
        hand_shake_type = 'Handshake Type: ' + hand_shake_type + ' (' + str(raw_data[0]) + ')'
        length = struct.unpack('>I', b'\0' + raw_data[1:4])[0]
        length = 'Length: ' + str(length)
        version = ntohs(struct.unpack('H', raw_data[4:6])[0])
        ver = tls_version(version)
        version = 'Version: ' + ver + f'(0x{version:04x})'
        random = ''
        for it in range(32):
            random += (hex(raw_data[6 + it]).replace('0x', '')).zfill(2)
        random = 'Random: ' + random
        session_id_length = raw_data[38]
        session_id = ''
        for it in range(session_id_length):
            session_id += hex(raw_data[39 + it]).replace('0x', '').zfill(2)

        session_id = 'Session ID: ' + session_id
        cipher_suites_length = struct.unpack('>H', raw_data[39 + session_id_length:41 + session_id_length])[0]
        cuites = []
        for i in range(0, cipher_suites_length, 2):
            val = struct.unpack('>H', raw_data[session_id_length + 41 + i:session_id_length + 43 + i])[0]
            cuites.append('Cipher Suite: ' + tls_cipher_suite(val))

        compression_method_length = raw_data[41 + cipher_suites_length + session_id_length]
        method = []
        for i in range(compression_method_length):
            method.append('Compression Methods: ' + str(raw_data[42 + cipher_suites_length + session_id_length + i]))
        extension_length = raw_data[
                           42 + cipher_suites_length + compression_method_length + session_id_length:
                           44 + cipher_suites_length + compression_method_length + session_id_length]
        extension_length = struct.unpack('>H', extension_length)[0]

        extension_length = 'Extension Length: ' + str(extension_length)
        compression_method_length = 'Compression Methods Length: ' + str(compression_method_length)
        cipher_suites_length = 'Cipher Suites Length: ' + str(cipher_suites_length)
        session_id_length = 'Session ID Length: ' + str(session_id_length)
        return hand_shake_type, length, version, random, session_id_length, session_id, cipher_suites_length, \
               cuites, compression_method_length, method, extension_length
    else:
        return 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0


def tls_hand_shake_server(data, offset):
    raw_data = data[offset:]
    if raw_data[0] == 2 and len(raw_data) >= 42:
        hand_shake_type = tls_hand_shake_type(raw_data[0])
        hand_shake_type = 'Handshake Type: ' + hand_shake_type + ' (' + str(raw_data[0]) + ')'
        length = struct.unpack('>I', b'\0' + raw_data[1:4])[0]
        length = 'Length: ' + str(length)
        version = ntohs(struct.unpack('H', raw_data[4:6])[0])
        ver = tls_version(version)
        version = 'Version: ' + ver + f'(0x{version:04x})'
        random = ''
        for it in range(32):
            random += (hex(raw_data[6 + it]).replace('0x', '')).zfill(2)
        random = 'Random: ' + random
        session_id_length = raw_data[38]
        session_id = ''
        for it in range(session_id_length):
            session_id += hex(raw_data[39 + it]).replace('0x', '').zfill(2)

        session_id = 'Session ID: ' + session_id
        cipher_suite = struct.unpack('>H', raw_data[39 + session_id_length:41 + session_id_length])[0]
        cipher_suite = tls_cipher_suite(cipher_suite)
        cipher_suite = 'Cipher Suite: ' + cipher_suite
        compression_method = raw_data[41 + session_id_length]
        compression_method = 'Compression Method: ' + str(compression_method)
        extension_length = struct.unpack('>H', raw_data[42 + session_id_length:44 + session_id_length])[0]
        extension_length = 'Extensions Length: ' + str(extension_length)
        session_id_length = 'Session ID Length: ' + str(session_id_length)
        return hand_shake_type, length, version, random, session_id_length, session_id, \
               cipher_suite, compression_method, extension_length
    else:
        return 0, 0, 0, 0, 0, 0, 0, 0, 0


def tls_key_exchange(data, offset):
    raw_data = data[offset:]
    if raw_data[0] == 16 and len(raw_data) >= 5:
        hand_shake_type = tls_hand_shake_type(raw_data[0])
        hand_shake_type = 'Handshake Type: ' + hand_shake_type + ' (' + str(raw_data[0]) + ')'
        length = struct.unpack('>I', b'\0' + raw_data[1:4])[0]
        length = 'Length: ' + str(length)
        public_key_length = raw_data[4]
        public_key = ''
        for i in range(public_key_length):
            public_key += hex(raw_data[5 + i]).replace('0x', '').zfill(2)
        public_key_length = 'PubKey Length: ' + str(public_key_length)
        public_key = 'Pubkey: ' + public_key
        return hand_shake_type, length, public_key_length, public_key
    else:
        return 0, 0, 0, 0


def tls_new_session_ticket(data, offset):
    raw_data = data[offset:]
    if raw_data[0] == 4 and len(raw_data) >= 42:
        hand_shake_type = tls_hand_shake_type(raw_data[0])
        hand_shake_type = 'Handshake Type: ' + hand_shake_type + ' (' + str(raw_data[0]) + ')'
        length = struct.unpack('>I', b'\0' + raw_data[1:4])[0]
        length = 'Length: ' + str(length)
        time_hint = struct.unpack('>I', raw_data[4:8])[0]
        time_hint = 'Session Ticket Lifetime Hint: ' + str(time_hint)
        session_ticket_len = struct.unpack('>H', raw_data[8:10])[0]
        ticket = ''
        for i in range(session_ticket_len):
            ticket += hex(raw_data[10 + i]).replace('0x', '').zfill(2)
        ticket = 'Session Ticket: ' + ticket
        session_ticket_len = 'Session Ticket Length: ' + str(session_ticket_len)
        return hand_shake_type, length, time_hint, session_ticket_len, ticket
    else:
        return 0, 0, 0, 0, 0


def tls_server_hello_done(data, offset):
    raw_data = data[offset:]
    if raw_data[0] == 14 and len(raw_data) >= 4:
        hand_shake_type = tls_hand_shake_type(raw_data[0])
        hand_shake_type = 'Handshake Type: ' + hand_shake_type + ' (' + str(raw_data[0]) + ')'
        length = struct.unpack('>I', b'\0' + raw_data[1:4])[0]
        length = 'Length: ' + str(length)
        return hand_shake_type, length
    else:
        return 0, 0


def server_key_exchange(data, offset):
    raw_data = data[offset:]
    if raw_data[0] == 12 and len(raw_data) >= 12:
        hand_shake_type = tls_hand_shake_type(raw_data[0])
        hand_shake_type = 'Handshake Type: ' + hand_shake_type + ' (' + str(raw_data[0]) + ')'
        length = struct.unpack('>I', b'\0' + raw_data[1:4])[0]
        length = 'Length: ' + str(length)
        curve_type = '0x' + hex(raw_data[4]).replace('0x', '').zfill(2)
        curve_type = 'Curve Type: ' + curve_type
        curve_name = ntohs(struct.unpack('H', raw_data[5:7])[0])
        curve_name = 'Named Curve: 0x' + hex(curve_name).replace('0x', '').zfill(4)
        pubkey_len = raw_data[7]
        pubkey = ''
        for i in range(pubkey_len):
            pubkey = pubkey + hex(raw_data[8 + i]).replace('0x', '')
        pubkey = 'Pubkey: ' + pubkey
        sig_algorithm = struct.unpack('>H', raw_data[8 + pubkey_len: 10 + pubkey_len])[0]
        sig_algorithm = 'Signature Algorithm: ' + hex(sig_algorithm)
        sig_len = struct.unpack('>H', raw_data[10 + pubkey_len: 12 + pubkey_len])[0]
        sig = ''
        for i in range(sig_len):
            sig = sig + hex(raw_data[12 + pubkey_len + i]).replace('0x', '')
        sig = 'Signature: ' + sig
        sig_len = 'Signature Length: ' + str(sig_len)
        pubkey_len = 'Pubkey Length: ' + str(pubkey_len)
        return hand_shake_type, length, curve_type, curve_name, pubkey_len, pubkey, sig_algorithm, sig_len, sig
    else:
        return 0, 0, 0, 0, 0, 0, 0, 0, 0


def tls_certificate(data, offset):
    raw_data = data[offset:]
    if raw_data[0] == 11 and len(raw_data) >= 5:
        hand_shake_type = tls_hand_shake_type(raw_data[0])
        hand_shake_type = 'Handshake Type: ' + hand_shake_type + ' (' + str(raw_data[0]) + ')'
        length = struct.unpack('>I', b'\0' + raw_data[1:4])[0]
        length = 'Length: ' + str(length)
        certificates_len = struct.unpack('>I', b'\0' + raw_data[4:7])[0]
        certificate = []
        if certificates_len:
            cer_len = struct.unpack('>I', b'\0' + raw_data[7:10])[0]
            analysis_cer = raw_data[10: 10 + cer_len]
            detail = analysis_certification_dire(analysis_cer)
            cer = ''
            for it in range(cer_len):
                cer = cer + hex(raw_data[10 + it]).replace('0x', '')
            total_len = cer_len + 3
            cer = 'Certificate: ' + cer
            certificate.append(('Certificate Length: ' + str(cer_len), cer, detail))
            flag = certificates_len - total_len
            while flag:
                cer_len = struct.unpack('>I', b'\0' + raw_data[total_len + 7: + total_len + 10])[0]
                analysis_cer = raw_data[total_len + 10: total_len + 10 + cer_len]
                detail = analysis_certification_dire(analysis_cer)
                cer = ''
                for it in range(cer_len):
                    cer = cer + hex(raw_data[total_len + 10 + it]).replace('0x', '')
                certificate.append(('Certificate Length: ' + str(cer_len), cer, detail))
                flag -= (cer_len + 3)
                total_len += cer_len + 3

        certificates_len = 'Certificates Length: ' + str(certificates_len)
        return hand_shake_type, length, certificates_len, certificate
    else:
        return 0, 0, 0, None


def analysis_http(data, offset):
    raw_data = str(data[offset:], 'utf-8', errors='ignore')
    # content length
    pattern = re.compile(r'Content-Length:.*\r\n')
    data_len = re.findall(pattern, raw_data)
    if data_len:
        data_len = int(data_len[0].split(':')[-1].split('\r')[0].replace(' ', ''))
    else:
        data_len = 0
    pattern = re.compile(r'Content-Type:.*\r\n')
    data_type = re.findall(pattern, raw_data)
    if data_type:
        data_type = data_type[0].split(':')[-1].split('\r')[0].replace(' ', '')
    else:
        data_type = ''
    return data[offset:], data_len, data_type
