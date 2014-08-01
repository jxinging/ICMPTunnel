# coding: utf8
__author__ = 'JinXing'

import os
import socket
import select
from SocketServer import TCPServer, ThreadingMixIn, StreamRequestHandler
from tunnel import Tunnel
from helper import *


class MyTCPServer(TCPServer):
    request_queue_size = 1024
    allow_reuse_address = True

    def __init__(self, *args, **kwargs):
        TCPServer.__init__(self, *args, **kwargs)
        self._id = os.getpid() & 0xFF00

    def finish_request(self, request, client_address):
        """Finish one request by instantiating RequestHandlerClass."""
        id_ = self._id
        self._id += 1
        self.RequestHandlerClass(id_, request, client_address, self)


class ThreadingTCPServer(ThreadingMixIn, MyTCPServer):
# class ThreadingTCPServer(MyTCPServer):
    daemon_threads = True


class ClientRequestHandler(StreamRequestHandler):
    def __init__(self, id_, *args, **kwargs):
        self._id = id_
        self._peer = config["peer"]
        # self._tgt_ip = config["target_ip"]
        # self._tgt_port = config["target_port"]
        self._tcp_sock = None
        self._icmp_sock = None
        self._thread = None
        StreamRequestHandler.__init__(self, *args, **kwargs)

    def setup(self):
        StreamRequestHandler.setup(self)
        self._tcp_sock = self.request
        icmp = socket.getprotobyname("icmp")
        self._icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        # send_data = ICMPPacket.create(ICMP_ECHO, 0, self._id, 0, "")
        # self._icmp_sock.sendto(send_data, (self._peer, 0))
        seq = 0
        send_data = ICMPPacket.create(ICMP_ECHO, 0, self._id, seq, "xnew")
        logger.debug("[%d]# new connection", self._id)
        while self._tcp_sock:
            self._icmp_sock.sendto(send_data, (self._peer, 0))
            rfds, _, _ = select.select([self._icmp_sock], [], [], 0.1)
            if not rfds:
                continue
            data, addr = self._icmp_sock.recvfrom(MAX_BUF_LEN)
            _, id_, r_seq, payload = ICMPPacket.parse(data)
            # print addr[0], self._peer, id_, self._id, r_seq, seq
            if addr[0] == self._peer and id_ == self._id and \
                            r_seq == seq and payload == "xnew":
                logger.debug("[%d]# conn success", self._id)
                break

    def handle(self):
        StreamRequestHandler.handle(self)
        t = Tunnel(self._tcp_sock, self._icmp_sock, self._peer, self._id)
        t.loop()

    def finish(self):
        StreamRequestHandler.finish(self)
        self._icmp_sock.close()
        self._icmp_sock = None
        self._tcp_sock = None


def client_test():
    server = ThreadingTCPServer(("0.0.0.0", 1199), ClientRequestHandler)
    sa = server.socket.getsockname()
    print "Serving on", sa[0], "port", sa[1], "..."
    server.serve_forever(0.5)

if __name__ == "__main__":
    client_test()