# coding: utf8
__author__ = 'JinXing'

import os
import time
import socket
import select
import errno
from config import *
from tunnel import ClientTunnel
from baseServer import BaseServer


class ClientServer(BaseServer):
    def __init__(self, peer, bind_port, bind_ip=None):
        BaseServer.__init__(self)
        self.icmp_type = 8

        if bind_ip is None:
            bind_ip = ""
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.peer_host = peer
        self._id = 0xFF00 & os.getpid()

        self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                       socket.getprotobyname("icmp"))

        self.select_socks = None
        
    def new_id(self):
        id_ = self._id
        self._id += 1
        return id_

    def check_seq(self, icmp_p):
        if icmp_p.seq % 2 != 1 and icmp_p.seq not in (0,):
            # logger.debug("check_seq() seq no error: %d", icmp_p.seq)
            return False
        return BaseServer.check_seq(self, icmp_p)

    def recv_icmp(self):
        icmp_p = BaseServer.recv_icmp(self)
        if icmp_p and icmp_p.id not in self.id_tunnel_map:
            return
        return icmp_p

    def process_listen_sock(self):
        cli_sock, cli_addr = self.listen_sock.accept()
        cli_sock.setblocking(False)
        self.tcp_socks.add(cli_sock)
        self.update_select_socks()
        logger.debug("accept connect: %s", str(cli_sock.getpeername()))

    def process_recv_tcp(self, sock):
        tun_id = self.sock_id_map.get(sock, None)
        if not tun_id or tun_id not in self.id_tunnel_map:
            tun_id = self.new_id()
            logger.debug("new tunnel: %d", tun_id)
            self.sock_id_map[sock] = tun_id
            try:
                self.id_tunnel_map[tun_id] = ClientTunnel(
                    tun_id, sock, self.icmp_sock, self.peer_host)
            except Exception, e:
                logger.error("create new tunnel failed: %s", e)
                return

        return BaseServer.process_recv_tcp(self, sock)

    def serve_active(self):
        self.listen_sock.bind((self.bind_ip, self.bind_port))
        self.listen_sock.listen(1024)

    def serve_forever(self, poll_interval=0.01):
        self.update_select_socks()
        empty_list = ()
        while 1:
            r_socks, _, _ = select.select(self.select_socks,
                                       empty_list, empty_list, poll_interval)

            if self.listen_sock in r_socks:
                self.process_listen_sock()

            if self.icmp_sock in r_socks:
                self.process_recv_icmp()

            for sock in [x for x in self.tcp_socks if x in r_socks]:
                self.process_recv_tcp(sock)

            self.process_tcp_bufs()
            self.process_icmp_bufs()

if __name__ == "__main__":
    #s = ClientServer("14.17.123.11", 9140)
    #s = ClientServer("usvps.jinxing.me", 9140)
    #s = ClientServer("10.19.190.21", 9140)
    s = ClientServer("121.201.1.110", 9140)
    s.serve_active()
    logging.info("Serving %s", str(s.listen_sock.getsockname()))
    s.serve_forever()
