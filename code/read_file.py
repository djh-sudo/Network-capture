import os
import struct
import time

from protocol_format import Protocol
from analysis_protocol import handle_raw_data, handle_tcp_payload


def read(file_path: str):
    pro_array = []
    send_rev = {}
    tcp_segment = {}
    un_pair = {}
    if file_path.endswith('.pcap'):
        with open(file_path, 'rb') as fp:
            data = fp.read()
            # pcap_header = {'magic_number': data[0:4], 'version_major': data[4:6], 'version_minor': data[6:8],
            #                'thiszone': data[8:12], 'sigfigs': data[12:16], 'snaplen': data[16:20],
            #                'linktype': data[20:24]}
            i = 24
            count_number = 0
            while i < len(data):
                block = Protocol()

                pcap_packet_header = {'GMTtime': data[i:i + 4], 'MicroTime': data[i + 4:i + 8],
                                      'caplen': data[i + 8:i + 12], 'len': data[i + 12:i + 16]}
                pcap_len = struct.unpack('I', pcap_packet_header['len'])[0]
                time_int = struct.unpack('I', pcap_packet_header['GMTtime'])[0]
                time_local = time.localtime(time_int)
                dt = time.strftime("%Y-%m-%d %H:%M:%S", time_local)
                ms = struct.unpack('I', pcap_packet_header['MicroTime'])[0]
                time_stamp = (time_local.tm_hour * 24 * 60 +
                              time_local.tm_min * 60 + time_local.tm_sec) * 1000000 + ms

                send_rev[time_stamp] = pcap_len
                block.time = dt
                block.len = pcap_len
                i = i + 16
                raw_data = data[i:i + pcap_len]
                block.data = raw_data
                block, _ = analysis_data(raw_data, block)
                i = i + pcap_len
                if not block:
                    continue
                if 'TCP' in block.protocol:
                    key_before = block.src_ip + block.des_ip + block.src_port + block.des_port \
                                 + str(block.seq + block.payload_len)
                    key_after = block.src_ip + block.des_ip + block.src_port + block.des_port \
                                + str(block.seq)
                    if _:
                        if block.payload_len - _ > 0:
                            block.segment = block.payload_len - _

                            tcp_segment[key_before] = count_number
                            un_pair[key_before] = _
                        if block.payload_len - _ < 0:
                            tcp_segment[key_before] = count_number
                            un_pair[key_before] = 0

                    if key_after in un_pair:
                        cnt_num = tcp_segment[key_after]
                        index = un_pair[key_after]
                        header = pro_array[cnt_num].tcp_header + 14 + 20
                        if not pro_array[cnt_num].assemble_data:
                            block.assemble_data = pro_array[cnt_num].assemble_data \
                                                  + pro_array[cnt_num].data[index + header:] \
                                                  + block.data[header:]
                            block.frame.append(cnt_num)
                        else:
                            block.assemble_data = pro_array[cnt_num].assemble_data \
                                                  + block.data[header:]
                            block.frame = pro_array[cnt_num].frame + [cnt_num]
                        block.assemble_payload_len = len(block.assemble_data)
                        if handle_tcp_payload(block.assemble_data, 0, block) == len(block.assemble_data):
                            block.ok = True
                        else:
                            tcp_segment[key_before] = count_number
                            un_pair[key_before] = _
                if block:
                    pro_array.append(block)
                count_number += 1
    return pro_array, send_rev


def analysis_data(raw_data: [], block):
    res = handle_raw_data(raw_data, block)
    if res:
        if type(res).__name__ != 'bool':
            return block, res
        else:
            return block, 0
    else:
        return None, None


def read_dir(path: str):
    pro_array = []
    count_number = 0
    files = os.listdir(path)
    for file in files:
        tcp_segment = {}
        un_pair = {}
        pcap_file = path + '/' + file
        if not os.path.isdir(file) and pcap_file.endswith('.pcap'):
            with open(pcap_file, 'rb') as fp:
                data = fp.read()
                # pcap_header = {'magic_number': data[0:4], 'version_major': data[4:6], 'version_minor': data[6:8],
                #                'thiszone': data[8:12], 'sigfigs': data[12:16], 'snaplen': data[16:20],
                #                'linktype': data[20:24]}
                i = 24
                while i < len(data):
                    block = Protocol()

                    pcap_packet_header = {'GMTtime': data[i:i + 4], 'MicroTime': data[i + 4:i + 8],
                                          'caplen': data[i + 8:i + 12], 'len': data[i + 12:i + 16]}
                    pcap_len = struct.unpack('I', pcap_packet_header['len'])[0]
                    time_int = struct.unpack('I', pcap_packet_header['GMTtime'])[0]
                    time_local = time.localtime(time_int)
                    dt = time.strftime("%Y-%m-%d %H:%M:%S", time_local)
                    block.time = dt
                    block.len = pcap_len
                    i = i + 16
                    raw_data = data[i:i + pcap_len]
                    block.data = raw_data
                    block, _ = analysis_data(raw_data, block)
                    i = i + pcap_len
                    if not block:
                        continue
                    if 'TCP' in block.protocol:
                        key_before = block.src_ip + block.des_ip + block.src_port + block.des_port \
                                     + str(block.seq + block.payload_len)
                        key_after = block.src_ip + block.des_ip + block.src_port + block.des_port \
                                    + str(block.seq)
                        if _:
                            if block.payload_len - _ > 0:
                                block.segment = block.payload_len - _

                                tcp_segment[key_before] = count_number
                                un_pair[key_before] = _
                            if block.payload_len - _ < 0:
                                tcp_segment[key_before] = count_number
                                un_pair[key_before] = 0

                        if key_after in un_pair:
                            cnt_num = tcp_segment[key_after]
                            index = un_pair[key_after]
                            header = pro_array[cnt_num].tcp_header + 14 + 20
                            if not pro_array[cnt_num].assemble_data:
                                block.assemble_data = pro_array[cnt_num].assemble_data \
                                                      + pro_array[cnt_num].data[index + header:] \
                                                      + block.data[header:]
                                block.frame.append(cnt_num)
                            else:
                                block.assemble_data = pro_array[cnt_num].assemble_data \
                                                      + block.data[header:]
                                block.frame = pro_array[cnt_num].frame + [cnt_num]
                            block.assemble_payload_len = len(block.assemble_data)
                            if handle_tcp_payload(block.assemble_data, 0, block) == len(block.assemble_data):
                                block.ok = True
                            else:
                                tcp_segment[key_before] = count_number
                                un_pair[key_before] = _

                    if block:
                        pro_array.append(block)
                    count_number += 1
    return pro_array
