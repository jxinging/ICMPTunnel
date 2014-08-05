# coding: utf8
__author__ = 'JinXing'

from message import ClientMessage, ServerMessage


class BaseTunnel(object):
    MessageCls = None

    def __init__(self, id_, send_seq, recv_seq, socket):
        self.id = id_
        self.send_seq = send_seq
        self.recv_seq = recv_seq
        self.socket = socket

        self.tcp_send_bufs = []
        self.icmp_send_bufs = {}    # seq:data
        self.icmp_recv_bufs = {}    # seq:data
        self.icmp_wait_ack_bufs = {}    # seq: [timeout, data]
        self.block_timeout = None
        self.closing = 0
        self.peer = None

    def update_send_seq(self):
        self.send_seq = self.next_send_seq()
        return self.send_seq

    def next_send_seq(self):
        return self.send_seq + 2

    def update_recv_seq(self):
        self.recv_seq = self.next_recv_seq()
        return self.recv_seq

    def next_recv_seq(self):
        return self.recv_seq + 2

    def send_icmp_ack(self, ack_seq):
        pass

    def send_icmp_close(self):
        pass


class ClientTunnel(BaseTunnel):
    MessageCls = ClientMessage

    def __init__(self, id_, socket, server):
        # seq 0-9 保留特殊使用, client 发出的包seq为奇数
        BaseTunnel.__init__(self, id_, 10, 11, socket)
        self.peer = server


class ServerTunnel(BaseTunnel):
    MessageCls = ServerMessage

    def __init__(self, id_, socket, client):
        # seq 0-9 保留特殊使用, server 发出的包seq为偶数
        BaseTunnel.__init__(self, id_, 11, 10, socket)
        self.peer = client