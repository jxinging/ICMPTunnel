# coding: utf8
__author__ = 'JinXing'

import socket
import select
import time
import errno
from config import *
from tunnel import ServerTunnel
from baseServer import BaseServer


class Server(BaseServer):
    def __init__(self, target_host, target_port):
        BaseServer.__init__(self)
        self.icmp_type = 0
        self.target_host = target_host
        self.target_port = target_port
        self.icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                      socket.getprotobyname("icmp"))

    # TODO: 异步建立　TCP　连接
    def new_tunnel(self, peer, tun_id, host=None, port=None):
        if host is None:
            host = self.target_host
        if port is None:
            port = self.target_port
        logger.info("new connection: %s#%d => %s:%d", peer, tun_id, host, port)
        ip = socket.gethostbyname(host)
        sock = socket.create_connection((ip, port))
        sock.setblocking(False)
        self.tcp_socks.add(sock)
        self.update_select_socks()
        self.sock_id_map[sock] = tun_id
        self.id_tunnel_map[tun_id] = ServerTunnel(tun_id, sock, self.icmp_sock, peer)
        return self.id_tunnel_map[tun_id]

    def recv_icmp(self):
        icmp_p = BaseServer.recv_icmp(self)
        # if icmp_p and icmp_p.id not in self.id_tunnel_map:
        #     try:
        #         self.new_tunnel(icmp_p.addr, icmp_p.id, icmp_p.seq)
        #     except Exception, e:
        #         logger.debug("create new tunnel failed: %s", e)
        #         return None
        return icmp_p

    def serve_forever(self, poll_interval=0.01):
        self.update_select_socks()
        empty_list = ()
        while 1:
            st = time.time()
            r_socks, _, _ = select.select(self.select_socks,
                                          empty_list, empty_list, poll_interval)

            if self.icmp_sock in r_socks:
                self.process_recv_icmp()

            for sock in [x for x in self.tcp_socks if x in r_socks]:
                self.process_recv_tcp(sock)

            self.process_tcp_bufs()
            self.process_icmp_bufs()

            cost_time = time.time()-st
            if cost_time < poll_interval:
                pass
                # time.sleep(poll_interval-cost_time)

if __name__ == "__main__":
    s = Server("127.0.0.1", 1080)
    #s = Server("121.201.1.110", 9141)
    #s = Server("usvps.jinxing.me", 80)
    logger.info("ICMP Serving ...")
    s.serve_forever()
