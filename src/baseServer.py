# coding: utf8
__author__ = 'JinXing'

import socket
from config import *
from _icmp import ICMPPocket


class BaseServer(object):
    def __init__(self):
        self.icmp_sock = None
        self.listen_sock = None

        self.sock_id_map = {}
        self.id_tunnel_map = {}

        self.tcp_socks = set()
        self.blocked_socks = set()

        self.select_socks = None

    def new_id(self):
        raise NotImplemented

    def socket_close(self, sock):
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()
        self.tcp_socks.remove(sock)

    def send_icmp(self, peer, id_, data, seq=None, type_=8):
        tun = self.id_tunnel_map[id_]
        if seq is None:
            seq = tun.next_send_seq()

        ICMPPocket(type_, id_, seq, MAGIC_ID+data).sendto(self.icmp_sock, peer)

    def recv_icmp(self):
        icmp_p = ICMPPocket.parse(self.icmp_sock, MAX_BUF_LEN)
        if not icmp_p.data.startswith(MAGIC_ID) or icmp_p.id not in self.id_tunnel_map:
            return None

        icmp_p.data = icmp_p.data[len(MAGIC_ID):]
        return icmp_p

    def update_select_socks(self):
        socks = list(self.tcp_socks)
        socks.append(self.icmp_sock)
        if self.listen_sock:
            socks.append(self.listen_sock)
        self.select_socks = socks
        return self.select_socks

    def new_tunnel(self):
        raise NotImplemented

    def serve_forever(self, poll_interval):
        raise  NotImplemented

if __name__ == "__main__":
    print dir(BaseServer())