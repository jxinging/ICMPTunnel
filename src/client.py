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
        self._id = (self._id+1) % 0xFFFF
        return id_

    def new_tunnel(self, cli_sock, tun_id, host=None, port=None):
        logger.info("new tunnel %s => %s#%d => %s:%d",
                    cli_sock.getpeername(), self.peer_host, tun_id, host, port)
        tun = ClientTunnel(tun_id, cli_sock, self.icmp_sock, self.peer_host)
        tun.send_icmp_connect(host, port)
        self.sock_id_map[cli_sock] = tun_id
        self.id_tunnel_map[tun_id] = tun
        return tun

    def recv_icmp(self):
        icmp_p = BaseServer.recv_icmp(self)
        if icmp_p and icmp_p.id not in self.id_tunnel_map:
            return
        return icmp_p

    def recv_tcp(self, sock, tun):
        data, host, port = BaseServer.recv_tcp(self, sock, tun)

        # 只有第一次接收到一个连接的数据时才解析代理参数
        if not tun and data.find(" HTTP/") > 0:
            idx = data.find("Host:")
            if idx < 0:  # not find Host:
                return data, host, port

            start_idx = idx + 5     # len("Host:") = 5
            end_idx = data.find("\r", start_idx)
            http_host_str = data[start_idx:end_idx].strip()
            if http_host_str.find(":") > 0:
                host, port = http_host_str.split(":")
                port = int(port)
            else:
                host = http_host_str
                port = 80
            logger.info("setup http proxy to %s:%d", host, port)

        return data, host, port

    def process_listen_sock(self):
        cli_sock, cli_addr = self.listen_sock.accept()
        cli_sock.setblocking(False)
        self.tcp_socks.add(cli_sock)
        self.update_select_socks()
        logger.debug("accept connect: %s", str(cli_sock.getpeername()))

    def process_recv_tcp(self, sock):
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
    s = ClientServer("usvps.jinxing.me", 9140)
    #s = ClientServer("10.19.190.21", 9140)
    #s = ClientServer("121.201.1.110", 9140)
    s.serve_active()
    logging.info("Serving %s", str(s.listen_sock.getsockname()))
    s.serve_forever()
