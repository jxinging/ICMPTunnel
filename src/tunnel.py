# coding: utf8
__author__ = 'JinXing'

import time
from _icmp import ICMPPocket
from message import (
    ClientMessage, ServerMessage, Message,
    MSG_TYPE_ACK, MSG_TYPE_CLOSE, MSG_TYPE_DATA
)
from config import *


class BaseTunnel(object):
    MessageCls = Message
    ICMP_TYPE = 8

    def __init__(self, id_, send_seq, recv_seq, socket, icmp_socket, peer):
        self.id = id_
        self.send_seq = send_seq
        self.recv_seq = recv_seq
        self.socket = socket    # tcp socket
        self.icmp_socket = icmp_socket

        self.tcp_send_bufs = []
        self.icmp_send_bufs = {}    # seq:data
        self.icmp_recv_bufs = {}    # seq:data
        self.icmp_wait_ack_bufs = {}    # seq: [timeout, data]
        self.last_live = 0   # 上一次收到数据包的时间戳
        self.close_timeout = 0
        self.peer = peer
        self.trans_bytes = 0

    def update_send_seq(self):
        self.send_seq = self.next_send_seq()
        return self.send_seq

    def next_send_seq(self):
        return (self.send_seq + 1) % ICMP_SEQ_MAX

    def update_recv_seq(self):
        self.recv_seq = self.next_recv_seq()
        return self.recv_seq

    def next_recv_seq(self):
        return (self.recv_seq + 1) % ICMP_SEQ_MAX

    def send_icmp_ack(self, ack_seq):
        msg = self.MessageCls(MSG_TYPE_ACK, str(ack_seq))
        return self._send_icmp(msg.encode(), self.ICMP_TYPE)

    def send_icmp_close(self):
        msg = self.MessageCls(MSG_TYPE_CLOSE)
        return self._send_icmp(msg.encode(), self.ICMP_TYPE)

    def send_icmp_data(self, data, seq=None):
        msg = self.MessageCls(MSG_TYPE_DATA, data)
        return self._send_icmp(msg.encode(), self.ICMP_TYPE, seq)

    def _send_icmp(self, data, type_, seq=None):
        if seq is None:
            seq = self.send_seq
            self.update_send_seq()
        ICMPPocket(type_, self.id, seq, AUTH_STR+data).sendto(self.icmp_socket, self.peer)

    def process_icmp(self, icmp_p):
        msg = self.MessageCls.decode(icmp_p.data)
        if msg.from_type != self.MessageCls.ACCEPT_FROM:
            # logger.debug("msg from type error: %s", str(msg))
            return
        # logger.debug("msg: %s", str(msg))
        self.last_live = time.time()
        if msg.is_data():
            # logger.debug("icmp_p.seq: %d, self.recv_seq: %d", icmp_p.seq, self.recv_seq)
            send_ack = True
            if icmp_p.seq == self.recv_seq:
                self.tcp_send_bufs.append(msg.data)
                # logger.debug("transmit %d.%d", self.id, icmp_p.seq)
                next_seq = self.update_recv_seq()  # **

                while next_seq in self.icmp_recv_bufs:
                    # logger.debug("transmit %d.%d", self.id, next_seq)
                    self.tcp_send_bufs.append(self.icmp_recv_bufs[next_seq])
                    del self.icmp_recv_bufs[next_seq]
                    next_seq = self.update_recv_seq()   # **

            # recv_seq 接近最大值时小于当前 recv_seq 的包也接收
            elif icmp_p.seq > self.recv_seq or \
                            self.recv_seq > (ICMP_SEQ_MAX - MAX_BUFS_LEN):
                if len(self.icmp_recv_bufs) > MAX_BUFS_LEN:
                    logger.warn("icmp recv buf len %d", len(self.icmp_recv_bufs))
                    send_ack = False
                self.icmp_recv_bufs[icmp_p.seq] = msg.data
                logger.debug("cached icmp recv data %d.%d, cached pocket: %d",
                             icmp_p.id, icmp_p.seq, len(self.icmp_recv_bufs))
            elif icmp_p.seq < self.recv_seq:
                logger.debug("drop icmp recved data %d.%d", icmp_p.id, icmp_p.seq)

            if send_ack:
                self.send_icmp_ack(icmp_p.seq)

        elif msg.is_ack():
            self.update_recv_seq()  # **

            ack_seq = int(msg.data)
            if ack_seq in self.icmp_wait_ack_bufs:
                # logger.debug("ack %d.%d", self.id, ack_seq)
                del self.icmp_wait_ack_bufs[ack_seq]
            # Server.process_recv_icmp() 还会对该类消息进行其他处理

        elif msg.is_close():
            self.update_recv_seq()  # **
            # Server.process_recv_icmp() 还会对该类消息进行其他处理

        else:
            logger.warn("error msg type: %s", str(msg))

        return msg


class ClientTunnel(BaseTunnel):
    MessageCls = ClientMessage
    ICMP_TYPE = 8

    def __init__(self, id_, socket, icmp_sock, server):
        # BaseTunnel.__init__(self, id_, 10, 11, socket, icmp_sock, server)
        BaseTunnel.__init__(self, id_, 0, 0, socket, icmp_sock, server)


class ServerTunnel(BaseTunnel):
    MessageCls = ServerMessage
    ICMP_TYPE = 0

    def __init__(self, id_, socket, icmp_sock, client):
        # BaseTunnel.__init__(self, id_, 11, 10, socket, icmp_sock, client)
        BaseTunnel.__init__(self, id_, 0, 0, socket, icmp_sock, client)
