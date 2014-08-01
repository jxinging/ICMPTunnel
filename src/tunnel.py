# coding: utf8
__author__ = 'JinXing'

import time
import select
from helper import *


class Tunnel(object):
    def __init__(self, tcp_sock, icmp_sock, peer, id_, timeout=1000, retry=3):
        self._ts = tcp_sock
        self._is = icmp_sock
        self._peer = peer
        self._timeout = timeout/1000
        self._retry = retry
        self._status = {}
        self._icmp_id = id_
        self._seq = 0

    def log_prefix(self, seq=None):
        if seq is not None:
            return "[%d@%d]#" % (self._icmp_id, seq)
        else:
            return "[%d]#" % self._icmp_id

    def get_seq(self):
        self._seq = (self._seq + 1) % 0xFFFF
        return self._seq

    def loop(self):
        rlist = (self._ts.fileno(), self._is.fileno())
        empty_list = ()
        while self._ts:
            rfds, _, _ = select.select(rlist, empty_list, empty_list, 0.01)
            if self._ts.fileno() in rfds:
                self.recv_tcp()

            if self._is.fileno() in rfds:
                self.recv_icmp()

            now_time = time.time()
            for seq in self._status.keys():
                stat = self._status[seq]
                if now_time - stat["time"] >= self._timeout and stat["retry"] > 0:
                    logger.debug("%s retry: %d", self.log_prefix(seq), self._retry+1 - stat["retry"])
                    self.send_icmp(stat["data"])
                    stat["time"] = time.time()
                    stat["retry"] -= 1
                elif stat["retry"] <= 0:
                    logger.debug("%s failed", self.log_prefix(seq))
                    del self._status[seq]

    def recv_icmp(self):
        data = self._is.recv(MAX_BUF_LEN)
        logger.debug("%s recv_icmp: %s", self.log_prefix(), data)
        type_, id_, seq, payload = ICMPPacket.parse(data)
        if id_ != self._icmp_id:
            return

        if type_ == ICMP_ECHO:
            self.send_tcp(payload)
            send_data = ICMPPacket.create(ICMP_ECHO_REPLY, 0,
                                          self._icmp_id, seq, "%d" % len(data))
                                          # self._icmp_id, seq, socket.htons(len(data)))
            self.send_icmp(send_data)
        elif type_ == ICMP_ECHO_REPLY:
            if seq in self._status:
                del self._status[seq]
        else:
            logger.warn(u"未知消息类型: %r", type_)

    def recv_tcp(self):
        data = self._ts.recv(MAX_BUF_LEN)
        if len(data) == 0:
            logger.debug("%s close tunnel", self.log_prefix())
            self._ts.close()
            self._ts = None
            # TODO: 通知对端关闭连接
            return

        logger.debug("%s recv_tcp: %s", self.log_prefix(), data)
        seq = self.get_seq()
        send_data = ICMPPacket.create(ICMP_ECHO, 0,
                                      self._icmp_id, seq, data)
        self.send_icmp(send_data)
        self._status[seq] = {
            "data": send_data,
            "time": time.time(),
            "retry": self._retry
        }

    def send_tcp(self, data):
        self._ts.sendall(data)

    def send_icmp(self, data):
        self._is.sendto(data, (self._peer, 0))
