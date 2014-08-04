# coding: utf8
__author__ = 'JinXing'

import os
import socket
import select
import struct
import logging


logging.basicConfig(level=logging.DEBUG)
logger = logging

MAX_BUF_LEN = 4096
MAGIC_STR = "tunnel@tcpovericmp"
TCP_BUF_LEN = MAX_BUF_LEN - len(MAGIC_STR) - 20 - 8


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


class ClientServer(object):
    def __init__(self, peer, bind_port, bind_ip=None):
        if bind_ip is None:
            bind_ip = "0.0.0.0"
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                       socket.getprotobyname("icmp"))

        self.peer_host = peer
        self._id = 0xFF00 & os.getpid()
        self._sock_id_map = {}
        self._icmp_status = {}

        self.cli_socks = set()

    def serve_forever(self, poll_interval=0.1):
        self.server_sock.bind((self.bind_ip, self.bind_port))
        self.server_sock.listen(1024)

        while 1:
            rfds, _, _ = select.select([self.server_sock, self.icmp_sock] + list(self.cli_socks),
                                            [], [], poll_interval)
            # logger.debug("rfds: %s", str(rfds))
            if self.server_sock in rfds:
                cli_sock, cli_addr = self.server_sock.accept()
                cli_sock.setblocking(False)
                self.cli_socks.add(cli_sock)
                logger.debug("accept connect: %s", str(cli_sock.getpeername()))

            if self.icmp_sock in rfds:
                ret = self.recv_icmp()
                if ret:
                    stat = self._icmp_status[ret["id"]]
                    logger.debug("recv icmp[%d] %db", ret["id"], len(ret["data"]))
                    self.send_icmp(ret["id"], "/ack"+str(ret["seq"]), 0)    # 客户端 seq 0 专用于 ack
                    if ret["is_error_seq"]:
                        stat["icmp_recv_bufs"][ret["seq"]] = ret["data"]
                    else:
                        stat["datas"].append(ret["data"])
                        next_seq = ret["seq"] + 2
                        while next_seq in stat["icmp_recv_bufs"]:
                            stat["datas"].append(stat["icmp_recv_bufs"][next_seq])
                            next_seq += 2

            for sock in [x for x in self.cli_socks if x in rfds]:
                data = sock.recv(TCP_BUF_LEN)
                id_ = self._sock_id_map.get(sock, None)
                if len(data) == 0:
                    logger.debug("tcp socket closed: %s", sock.getpeername())
                    self.socket_close(sock)
                    if id_ is not None:
                        stat = self._icmp_status[id_]
                        stat["closing"] = 1
                    continue

                if id_ is None:
                    id_ = self.new_id()
                    logger.debug("new tunnel: %d", id_)
                    self._sock_id_map[sock] = id_
                    self._icmp_status[id_] = {
                        "id": id_,
                        "send_seq": 2,
                        "recv_seq": 3,
                        "closing": 0,
                        "socket": sock,
                        "datas": [],
                        "icmp_recv_bufs": {}
                    }
                else:
                    id_ = self._sock_id_map[sock]
                self.send_icmp(id_, data)

            for id_ in self._icmp_status.keys():
                stat = self._icmp_status[id_]
                if stat["datas"]:
                    datas = stat["datas"]
                    stat["datas"] = []
                    for data in datas:
                        if data == "/close":
                            stat["closing"] = 1
                            continue
                        try:
                            stat["socket"].sendall(data)
                        except Exception, e:
                            stat["datas"].append(data)
                            logger.debug("[%d]socket.sendall(): %s", stat["id"], e)

                if not stat["datas"] and stat["closing"]:
                    logger.debug("close tunnel: %d", id_)
                    sock = stat["socket"]
                    if sock in self.cli_socks:
                        self.socket_close(sock)
                    self.send_icmp(id_, "/close")     # 发送断开连接请求
                    del self._icmp_status[id_]

    def new_id(self):
        self._id += 1
        return self._id

    def socket_close(self, sock):
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()
        self.cli_socks.remove(sock)

    def send_icmp(self, id_, data, seq=None, type_=8):
        stat = self._icmp_status[id_]
        if seq is None:
            seq = stat["send_seq"]
            stat["send_seq"] += 2

        send_icmp(self.icmp_sock, self.peer_host, type_, 0, id_, seq, MAGIC_STR+data)

    def recv_icmp(self):
        _, _, _, _, id_, seq, data = recv_icmp(self.icmp_sock, MAX_BUF_LEN)
        if seq % 2 != 1:
            # logger.debug(u"server 发送的 icmp 包 seq 必须是奇数")
            return
        if not data.startswith(MAGIC_STR) or id_ not in self._icmp_status:
            return

        data = data[len(MAGIC_STR):]

        if seq != self._icmp_status[id_]["recv_seq"]:
            logger.info("error pocket seq: %d != %d", seq, self._icmp_status[id_]["recv_seq"])
            is_error_seq = True
        else:
            self._icmp_status[id_]["recv_seq"] = seq+2
            is_error_seq = False

        return {
            "id": id_,
            "seq": seq,
            "data": data,
            "is_error_seq": is_error_seq
        }

if __name__ == "__main__":
    # s = ClientServer("14.17.123.11", 9140)
    s = ClientServer("usvps.jinxing.me", 9140)
    logging.info("Serving %s", str(s.server_sock.getsockname()))
    s.serve_forever()
