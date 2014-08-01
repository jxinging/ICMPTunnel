# coding: utf8
__author__ = 'JinXing'

import os
import socket
import select
import struct
import logging


logging.basicConfig(level=logging.DEBUG)
logger = logging

MAX_BUF_LEN = 65536
MAGIC_STR = "tunnel@tcpovericmp"


def icmp_checksum(source_string):
    """
    I'm not too confident that this is right but testing seems
    to suggest that it gives the same answers as in_cksum in ping.c
    """
    sum_ = 0
    count_to = (len(source_string) / 2) * 2
    for count in xrange(0, count_to, 2):
        this = ord(source_string[count + 1]) * 256 + ord(source_string[count])
        sum_ += this
        sum_ &= 0xffffffff  # Necessary?

    if count_to < len(source_string):
        sum_ += ord(source_string[len(source_string) - 1])
        sum_ &= 0xffffffff  # Necessary?

    sum_ = (sum_ >> 16) + (sum_ & 0xffff)
    sum_ += (sum_ >> 16)
    answer = ~sum_
    answer &= 0xffff

    # Swap bytes. Bugger me if I know why.
    answer = answer >> 8 | (answer << 8 & 0xff00)

    return answer


def send_icmp(sock, host, type_, code, id_, seq, data):
    packfmt = "!BBHHH%ds" % (len(data))
    args = [type_, code, 0, id_, seq, data]
    args[2] = icmp_checksum(struct.pack(packfmt, *args))
    pocket = struct.pack(packfmt, *args)
    sock.sendto(pocket, (host, 0))


def recv_icmp(sock, buflen):
    raw, addr = sock.recvfrom(buflen)
    type_, code, checksum, id_, seq = struct.unpack("!BBHHH", raw[20:28])
    return addr[0], type_, code, checksum, id_, seq, raw[28:]


class ServerServer(object):
    def __init__(self, target_host, target_port):
        self.target_host = target_host
        self.target_port = target_port
        self.icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                       socket.getprotobyname("icmp"))
        self._sock_id_map = {}
        self._icmp_status = {}

        self.conn_socks = set()

    def serve_forever(self, poll_interval=0.01):
        while 1:
            rfds, _, _ = select.select([self.icmp_sock] + list(self.conn_socks),
                                            [], [], poll_interval)
            # logger.debug("rfds: %s", str(rfds))
            if self.icmp_sock in rfds:
                ret = self.recv_icmp()
                if ret:
                    logger.debug("recv_icmp: %s", str(ret))
                    stat = self._icmp_status[ret["id"]]
                    stat["datas"].append(ret["data"])

            for sock in [x for x in self.conn_socks if x in rfds]:
                data = sock.recv(MAX_BUF_LEN)
                id_ = self._sock_id_map.get(sock, None)
                stat = self._icmp_status[id_]
                if len(data) == 0:
                    logger.debug("tcp socket closed: %s", sock.getpeername())
                    self.socket_close(sock)
                    stat["closing"] = 1
                    continue

                self.send_icmp(stat["peer"], id_, data)

            for id_ in self._icmp_status.keys():
                stat = self._icmp_status[id_]
                print stat
                if stat["datas"]:
                    datas = stat["datas"]
                    stat["datas"] = []
                    for data in datas:
                        if data == "/close":
                            stat["closing"] = 1
                            continue
                        try:
                            stat["socket"].sendall(data)
                        except socket.error, e:
                            if e.errno in (socket.EAGAIN, socket.EWOULDBLOCK):
                                stat["datas"].append(data)
                            else:
                                logger.debug("[%d]socket.sendall(): %s", stat["id"], e)
                                self.socket_close(stat["socket"])

                if stat["closing"]:
                    logger.debug("close tunnel: %d", id_)
                    sock = stat["socket"]
                    if sock in self.conn_socks:
                        self.socket_close(sock)
                    self.send_icmp(stat["peer"], id_, "/close")     # 发送断开连接请求
                    del self._icmp_status[id_]

    def socket_close(self, sock):
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()
        self.conn_socks.remove(sock)

    def send_icmp(self, host, id_, data, type_=8):
        stat = self._icmp_status[id_]
        seq = stat["seq"]
        stat["seq"] += 1

        send_icmp(self.icmp_sock, host, type_, 0, id_, seq, MAGIC_STR+data)

    def recv_icmp(self):
        peer, _, _, _, id_, seq, data = recv_icmp(self.icmp_sock, MAX_BUF_LEN)
        if not data.startswith(MAGIC_STR):
            return
        data = data[len(MAGIC_STR):]

        if id_ not in self._icmp_status:
            self.new_connection(peer, id_, seq, self.target_host, self.target_port)

        return {
            "peer": peer,
            "id": id_,
            "seq": seq,
            "data": data
        }

    def new_connection(self, peer, id_, seq, host, port):
        ip = socket.gethostbyname(host)
        sock = socket.create_connection((ip, port))
        sock.setblocking(False)
        self.conn_socks.add(sock)
        self._sock_id_map[sock] = id_
        self._icmp_status[id_] = {
            "id": id_,
            "peer": peer,
            "seq": seq,
            "closing": 0,
            "socket": sock,
            "datas": []
        }
        return sock

if __name__ == "__main__":
    s = ServerServer("10.19.190.21", 80)
    logger.debug("ICMP Servicing ...")
    s.serve_forever()
