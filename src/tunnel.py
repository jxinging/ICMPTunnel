# coding: utf8
__author__ = 'JinXing'


class BaseTunnel(object):
    def __init__(self, id_, send_seq, recv_seq, socket):
        self.id = id_
        self.send_seq = send_seq
        self.recv_seq = recv_seq
        self.socket = socket

        self.tcp_send_bufs = []
        self.icmp_send_bufs = {}    # seq:data
        self.icmp_recv_bufs = {}    # seq:data
        self.block_timeout = None
        self.closing = 0
        self.peer = None

    def next_send_seq(self):
        seq = self.send_seq
        self.send_seq = self.get_next_send_seq()
        return seq

    def get_next_send_seq(self):
        return self.send_seq + 2

    def update_recv_seq(self):
        seq = self.recv_seq
        self.recv_seq += 2
        return seq

class ClientTunnel(BaseTunnel):
    def __init__(self, id_, socket):
        # seq 0-9 保留特殊使用, client 发出的包seq为奇数
        BaseTunnel.__init__(self, id_, 10, 11, socket)


class ServerTunnel(BaseTunnel):
    def __init__(self, id_, socket, client):
        # seq 0-9 保留特殊使用, server 发出的包seq为偶数
        BaseTunnel.__init__(self, id_, 11, 10, socket)
        self.peer = client