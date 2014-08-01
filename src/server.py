# coding: utf8
__author__ = 'JinXing'

import socket
import select
import threading
from tunnel import Tunnel
from helper import *


def build_icmp_socket():
    icmp_proto = socket.getprotobyname("icmp")
    return socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp_proto)


def build_tcp_connection(host, port):
    ip = socket.gethostbyname(host)
    conn = socket.create_connection((ip, port))
    return conn


def new_connection(id_, peer):
    tcp_conn = build_tcp_connection(config["target_ip"], config["target_port"])
    icmp_sock = build_icmp_socket()
    try:
        Tunnel(tcp_conn, icmp_sock, peer, id_).loop()
    finally:
        icmp_sock.close()
        tcp_conn.close()


def process_icmp_req(icmp_data, peer):
    type_, id_, seq, payload = ICMPPacket.parse(icmp_data)
    if type_ == ICMP_ECHO and seq == 0 and payload == "xnew":
        t = threading.Thread(target=new_connection, args=(id_, peer))
        t.start()


def forever_loop():
    server_sock = build_icmp_socket()
    while 1:
        rfds, _, _ = select.select([server_sock.fileno()], [], [], 0.1)
        if icmp_sock.fileno() in rfds:
            data, addr = server_sock.recvfrom(MAX_BUF_LEN)
            process_icmp_req(data, addr[0])


if __name__ == "__main__":
    print ""
    forever_loop()