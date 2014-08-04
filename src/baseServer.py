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
        self.icmp_type = None

    def new_id(self):
        raise NotImplemented

    def socket_close(self, sock):
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()
        self.tcp_socks.remove(sock)

    def send_icmp(self, peer, id_, data, seq=None, type_=None):
        if seq is None:
            tun = self.id_tunnel_map[id_]
            seq = tun.next_send_seq()
        if type_ is None:
            type_ = self.icmp_type
        ICMPPocket(type_, id_, seq, MAGIC_ID+data).sendto(self.icmp_sock, peer)

    def recv_icmp(self):
        icmp_p = ICMPPocket.parse(self.icmp_sock, MAX_BUF_LEN)
        if not icmp_p.data.startswith(MAGIC_ID):
            return None

        BaseServer.send_icmp(self, icmp_p.addr, icmp_p.id, "/ack"+str(icmp_p.seq), 0)
        if icmp_p.id in  self.id_tunnel_map and \
                        icmp_p.seq < self.id_tunnel_map[icmp_p.id]:
            return      # 丢弃已处理过的数据

        icmp_p.data = icmp_p.data[len(MAGIC_ID):]
        return icmp_p

    def update_select_socks(self):
        socks = list(self.tcp_socks)
        socks.append(self.icmp_sock)
        if self.listen_sock:
            socks.append(self.listen_sock)
        self.select_socks = socks
        return self.select_socks

    def check_seq(self, icmp_p):
        if icmp_p.id in self.id_tunnel_map:
            tun = self.id_tunnel_map[icmp_p.id]
            if tun.recv_seq != icmp_p.seq:
                return False
        return True

    def new_tunnel(self):
        raise NotImplemented

    def serve_forever(self, poll_interval):
        raise  NotImplemented

if __name__ == "__main__":
    print dir(BaseServer())