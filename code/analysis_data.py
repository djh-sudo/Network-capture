# -*- coding: utf-8 -*-
import os
import re
import sys
import requests
import numpy as np
import matplotlib
from matplotlib import font_manager as fm
from matplotlib import cm
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt


class ip_format:
    def __init__(self):
        self.ip_addr = ''
        self.recv_count = 0
        self.recv_size = 0
        self.send_count = 0
        self.send_size = 0
        self.location = ''


class ip_network:
    def __init__(self):
        self.src = ''
        self.des = ''
        self.send_size = 0
        self.send_count = 0


def analysis_ip_network(pro):
    if not pro:
        return
    send_size = {}
    send_count = {}
    res = []
    pair = set()
    for item in pro:
        src_ip = item.src_ip
        des_ip = item.des_ip
        if ':' in src_ip or ':' in des_ip:
            continue
        if src_ip + '-' + des_ip in pair:
            send_size[src_ip + '-' + des_ip] += item.len
            send_count[src_ip + '-' + des_ip] += 1
        else:
            pair.add(src_ip + '-' + des_ip)
            send_size[src_ip + '-' + des_ip] = item.len
            send_count[src_ip + '-' + des_ip] = 1
    for key in pair:
        packgae = ip_network()
        packgae.src = key.split('-')[0]
        packgae.des = key.split('-')[-1]
        packgae.send_size = send_size[key]
        packgae.send_count = send_count[key]
        res.append(packgae)
    return res


def analysis_ip(pro):
    if not pro:
        return [], [], []
    src_count = {}
    des_count = {}
    src_len = {}
    des_len = {}
    res = []
    for item in pro:
        src_ip = item.src_ip
        des_ip = item.des_ip
        if src_ip in src_len:
            src_len[src_ip] += item.len
            src_count[src_ip] += 1
        else:
            src_len[src_ip] = item.len
            src_count[src_ip] = 1
        if des_ip in des_len:
            des_len[des_ip] += item.len
            des_count[des_ip] += 1
        else:
            des_len[des_ip] = item.len
            des_count[des_ip] = 1

    all_ip = src_count.keys() | des_count.keys()

    for key in all_ip:
        package = ip_format()
        package.ip_addr = key
        match = checkip(key)
        if match:
            package.location = '本地/local'
        if key in src_count:
            package.send_count = src_count[key]
            package.send_size = src_len[key]
        else:
            package.send_count = 0
            package.send_size = 0
        if key in des_count:
            package.recv_count = des_count[key]
            package.recv_size = des_len[key]
        else:
            package.recv_count = 0
            package.recv_size = 0
        res.append(package)
    return res, src_len, des_len


def analysis_port(pro):
    if not pro:
        return
    tcp_src_count = {}
    tcp_des_count = {}

    udp_src_count = {}
    udp_des_count = {}

    for item in pro:
        src_port = item.src_port
        des_port = item.des_port
        protocol = item.protocol
        if 'TCP' in protocol:
            if src_port in tcp_src_count:
                tcp_src_count[src_port] += 1
            else:
                tcp_src_count[src_port] = 1
            if des_port in tcp_des_count:
                tcp_des_count[des_port] += 1
            else:
                tcp_des_count[des_port] = 1
        elif 'UDP' in protocol:
            if src_port in udp_src_count:
                udp_src_count[src_port] += 1
            else:
                udp_src_count[src_port] = 1
            if des_port in udp_des_count:
                udp_des_count[des_port] += 1
            else:
                udp_des_count[des_port] = 1
    return tcp_src_count, udp_src_count, tcp_des_count, udp_des_count


def plot_port(count: dict, tcp_flag=True):
    sizes = list(count.values())
    labels = list(count.keys())
    if tcp_flag:
        labels = add_tcp_lab(labels)
    else:
        labels = add_udp_lab(labels)
    fig, ax = plt.subplots()
    colors = cm.rainbow(np.arange(len(sizes)) / len(sizes))
    patches, texts, autotexts = ax.pie(sizes, labels=sizes, autopct='%1.0f%%',
                                       shadow=False, startangle=170, colors=colors)
    ax.axis('equal')
    proptease = fm.FontProperties()
    proptease.set_size('xx-small')
    plt.setp(autotexts, fontproperties=proptease)
    plt.setp(texts, fontproperties=proptease)
    ax.legend(labels, loc=2)
    plt.show()


def plot_all_port(tcp_src_count, udp_src_count, tcp_des_count, udp_des_count):
    all_data = {}
    for it in tcp_des_count:
        if 'TCP' + it in all_data:
            all_data['TCP' + it] += tcp_des_count[it]
        else:
            all_data['TCP' + it] = tcp_des_count[it]

    for it in tcp_src_count:
        if 'TCP' + it in all_data:
            all_data['TCP' + it] += tcp_src_count[it]
        else:
            all_data['TCP' + it] = tcp_src_count[it]

    for it in udp_src_count:
        if 'UDP' + it in all_data:
            all_data['UDP' + it] += udp_src_count[it]
        else:
            all_data['UDP' + it] = udp_src_count[it]

    for it in udp_des_count:
        if 'UDP' + it in all_data:
            all_data['UDP' + it] += udp_des_count[it]
        else:
            all_data['UDP' + it] = udp_des_count[it]

    sizes = list(all_data.values())
    labels = list(all_data.keys())
    labels = add_all_lab(labels)
    fig, ax = plt.subplots()
    colors = cm.rainbow(np.arange(len(sizes)) / len(sizes))
    patches, texts, autotexts = ax.pie(sizes, labels=sizes, autopct='%1.0f%%',
                                       shadow=False, startangle=170, colors=colors)
    ax.axis('equal')
    proptease = fm.FontProperties()
    proptease.set_size('xx-small')
    plt.setp(autotexts, fontproperties=proptease)
    plt.setp(texts, fontproperties=proptease)
    ax.legend(labels, loc=2)
    plt.show()


def plot_src(src: dict, number=10, show_flag=False):
    cache = './Cache/'
    if not os.path.exists(cache):
        os.mkdir(cache)
    name_list = list(src.keys())[:number]
    num_list = list(src.values())[:number]
    plt.figure(figsize=(10, 4))
    plt.bar(range(len(num_list)), num_list, tick_label=name_list, color=['r', 'g', 'b'])
    plt.grid(True)
    plt.xticks(rotation=15)
    plt.ylabel('send out traffic size(Bytes)')
    if show_flag:
        plt.show()
    else:
        plt.savefig(cache + 'ip_src.png', dpi=100)
    plt.close()


def plot_des(des: dict, number=10, show_flag=False):
    cache = './Cache/'
    if not os.path.exists(cache):
        os.mkdir(cache)
    name_list = list(des.keys())[:number]
    num_list = list(des.values())[:number]
    plt.figure(figsize=(10, 4.5))
    plt.bar(range(len(num_list)), num_list, tick_label=name_list, color=['r', 'g', 'b'])
    plt.grid(True)
    plt.xticks(rotation=20)
    plt.ylabel('recv out traffic size(Bytes)')
    if show_flag:
        plt.show()
    else:
        plt.savefig(cache + 'ip_des.png', dpi=100)
    plt.close()


def lookup(ip):
    # https://ip-api.com/
    # http://freeapi.ipip.net/
    # https://freeapi.ipip.net/
    URL = 'https://freeapi.ipip.net/' + ip
    try:
        r = requests.get(URL, timeout=3, headers={'User-agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) '
                                                                'AppleWebKit/537.36 (KHTML, like Gecko) '
                                                                'Chrome/64.0.3282.186 Safari/537.36'})
    except requests.RequestException as e:
        with open('log', 'a+') as f:
            sys.stdout = f
            print(e)
            f.close()
            sys.stdout = sys.__stdout__
        return ''
    if r.status_code != 200:
        return ''
    json_data = r.json()
    res = []
    if json_data:
        for i in range(5):
            if json_data[i]:
                res.append(json_data[i])
    # print('所在国家：' + json_data[0])
    # print('所在省份：' + json_data[1])
    # print('所在城市：' + json_data[2])
    # print('所在区域：' + json_data[3])
    # print('运营商：' + json_data[4])
    return ','.join(res)


def checkip(ip_addr):
    pat = re.compile(
        r'127\.'            r'|'
        r'10\.'             r'|'
        r'172\.1[6-9]\.'    r'|'
        r'172\.2[0-9]\.'    r'|'
        r'172\.3[0-1]\.'    r'|'
        r'192\.168\.'       r'|'
        r'255.255.255.255'  r'|'
        r'ff:ff:ff:ff:ff:ff')
    res = pat.match(ip_addr)
    return res


def add_udp_lab(lab: list):
    res = []
    for i in lab:
        if '53' == i:
            res.append(i + '(DNS)')
        elif '68' == i:
            res.append(i + '(BOOTP)')
        elif'69' == i:
            res.append(i + '(TFTP)')
        else:
            res.append(i)
    return res


def add_tcp_lab(lab: list):
    res = []
    for i in lab:
        if '80' == i:
            res.append(i + '(http)')
        elif '8080' == i:
            res.append(i + '(http)')
        elif '443' == i:
            res.append(i + '(ssl/tls)')
        elif '23' == i:
            res.append(i + '(telnet)')
        elif '21' == i:
            res.append(i + '(ftp)')
        elif '22' == i:
            res.append(i + '(ssh)')
        elif '25' == i:
            res.append(i + '(smtp)')
        else:
            res.append(i)
    return res


def add_all_lab(lab: list):
    res = []
    for i in lab:
        if 'UDP' in i:
            i = i.replace('UDP', '')
            if '53' == i:
                res.append(i + '(DNS)')
            elif '68' == i:
                res.append(i + '(BOOTP)')
            elif'69' == i:
                res.append(i + '(TFTP)')
            else:
                res.append(i)
        elif 'TCP' in i:
            i = i.replace('TCP', '')
            if '80' == i:
                res.append(i + '(http)')
            elif '8080' == i:
                res.append(i + '(http)')
            elif '443' == i:
                res.append(i + '(ssl/tls)')
            elif '23' == i:
                res.append(i + '(telnet)')
            elif '21' == i:
                res.append(i + '(ftp)')
            elif '22' == i:
                res.append(i + '(ssh)')
            elif '25' == i:
                res.append(i + '(smtp)')
            else:
                res.append(i)
        else:
            res.append(i)
    return res
