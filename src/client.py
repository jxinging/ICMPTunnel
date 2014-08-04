# coding: utf8
__author__ = 'JinXing'

import os
import time
import socket
import select
from config import *
from tunnel import ClientTunnel
from baseServer import BaseServer


class ClientServer(BaseServer):
    def __init__(self, peer, bind_port, bind_ip=None):
        if bind_ip is None:
            bind_ip = "0.0.0.0"
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

    def send_icmp(self, *args):
        return BaseServer.send_icmp(self, self.peer_host, *args)

    def check_seq(self, icmp_p):
        if icmp_p.seq % 2 != 1:
            return False
        return BaseServer.check_seq(self, icmp_p)

    def process_listen_sock(self):
        cli_sock, cli_addr = self.listen_sock.accept()
        cli_sock.setblocking(False)
        self.tcp_socks.add(cli_sock)
        self.update_select_socks()
        logger.debug("accept connect: %s", str(cli_sock.getpeername()))

    def process_icmp_sock(self):
        icmp_p = self.recv_icmp()
        if not icmp_p or not self.check_seq(icmp_p):
            return
        #
        # error_seq = False
        # if icmp_p.seq != self.id_tunnel_map[icmp_p.id].recv_seq:
        #     logger.info("error pocket seq: %d != %d",
        #                 icmp_p.seq, self.id_tunnel_map[icmp_p.id].recv_seq)
        #     error_seq = True
        #
        tun = self.id_tunnel_map[icmp_p.id]
        logger.debug("recv icmp[%d] %db", icmp_p["id"], len(icmp_p["data"]))
        #
        # if error_seq:
        #     tun.icmp_recv_bufs[icmp_p.seq] = icmp_p.data
        #     return
        #
        # tun.tcp_send_bufs.append(icmp_p.data)
        # next_seq = tun.next_send_seq()
        # while next_seq in tun.icmp_recv_bufs:
        #     tun.tcp_send_bufs.append(tun.icmp_recv_bufs[next_seq])
        #     next_seq = tun.next_send_seq()

        if icmp_p.seq == tun.recv_seq:
            tun.tcp_send_bufs.append(icmp_p.data)
            next_seq = tun.next_send_seq()
            while next_seq in tun.icmp_recv_bufs:
                data = tun.icmp_recv_bufs[next_seq]
                tun.tcp_send_bufs.append(data)
                next_seq = tun.next_send_seq()

        elif icmp_p.seq > tun.recv_seq:
            tun.icmp_recv_bufs[icmp_p.seq] = icmp_p.data
            tun.update_recv_seq()
        elif icmp_p.seq == 0:
            if icmp_p.data.startswith("/ack"):
                ack_seq = int(icmp_p["data"][len("/ack"):])
                tun = self.id_tunnel_map[icmp_p.id]
                sock = tun.socket
                if sock in self.blocked_socks:
                    self.tcp_socks.add(sock)
                    self.blocked_socks.remove(sock)
                    self.update_select_socks()
                del tun.icmp_send_bufs[ack_seq]
                logger.debug("tunnel %d ack %d", icmp_p.id, ack_seq)
                return
        else:
            logger.info("error pocket seq: %d != %d",
                        icmp_p.seq, tun.recv_seq)
            return

    def process_tcp_sock(self, sock):
        data = sock.recv(TCP_BUF_LEN)
        id_ = self.sock_id_map.get(sock, None)
        if len(data) == 0:
            logger.debug("tcp socket closed: %s", sock.getpeername())
            self.socket_close(sock)
            if id_ is not None:
                tun = self.id_tunnel_map[id_]
                tun["closing"] = 1
            return

        if id_ is None:
            id_ = self.new_id()
            logger.debug("new tunnel: %d", id_)
            self.sock_id_map[sock] = id_
            self.id_tunnel_map[id_] = ClientTunnel(id_, sock)
        else:
            id_ = self.sock_id_map[sock]

        tun = self.id_tunnel_map[id_]
        tun.icmp_send_bufs[tun.next_send_seq()] = data

    def process_send_bufs(self):
        for id_ in self.id_tunnel_map.keys():
            tun = self.id_tunnel_map[id_]

            # tcp
            if tun.tcp_send_bufs:
                bufs = tun.tcp_send_bufs
                tun.tcp_send_bufs = []
                for data in bufs:
                    if data == "/close":
                        tun["closing"] = 1
                        continue
                    try:
                        tun.socket.sendall(data)
                    except Exception, e:
                        tun.icmp_send_bufs.append(data)
                        logger.debug("[%d]socket.sendall(): %s", tun.id, e)

            # icmp
            if tun.icmp_send_bufs:
                min_seq = min(tun.icmp_send_bufs.keys())
                data = tun.icmp_send_bufs[min_seq]
                logger.debug("send icmp[%d] %db", id_, len(data))
                self.send_icmp(tun.id, data, min_seq)
                if len(tun.icmp_send_bufs) > MAX_BUFS_LEN and \
                                tun.socket not in self.blocked_socks:
                    self.blocked_socks.add(tun.socket)
                    self.tcp_socks.remove(tun.socket)
                    self.update_select_socks()
                    tun.block_timeout = time.time()+BLOCK_TIME
                    logger.debug("tunnel %d blocked", id_)

            # block timeout
            now_time = time.time()
            for sock in list(self.blocked_socks):
                id_ = self.sock_id_map[sock]
                tun = self.id_tunnel_map[id_]
                if now_time >= tun.block_timeout:
                    self.tcp_socks.add(sock)
                    self.blocked_socks.remove(sock)
                    self.update_select_socks()
                    tun.closing = 1
                    logger.debug("tunnel %d block timeout", tun.id)

            # 断开
            if not tun.tcp_send_bufs and tun.closing:
                logger.debug("close tunnel: %d", id_)
                sock = tun.socket
                if sock in self.tcp_socks:
                    self.socket_close(sock)
                self.send_icmp(id_, "/close")     # 发送断开连接请求
                del self.id_tunnel_map[id_]
                self.update_select_socks()

    def serve_forever(self, poll_interval=0.01):
        self.listen_sock.bind((self.bind_ip, self.bind_port))
        self.listen_sock.listen(1024)

        self.update_select_socks()
        empty_list = ()
        while 1:
            r_socks, _, _ = select.select(self.select_socks,
                                       empty_list, empty_list, poll_interval)

            if self.listen_sock in r_socks:
                self.process_listen_sock()

            if self.icmp_sock in r_socks:
                self.process_icmp_sock()

            for sock in [x for x in self.tcp_socks if x in r_socks]:
                self.process_tcp_sock(sock)

            self.process_send_bufs()

if __name__ == "__main__":
    s = ClientServer("14.17.123.11", 9140)
    # s = ClientServer("usvps.jinxing.me", 9140)
    logging.info("Serving %s", str(s.listen_sock.getsockname()))
    s.serve_forever()