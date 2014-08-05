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

    def process_listen_sock(self):
        cli_sock, cli_addr = self.listen_sock.accept()
        cli_sock.setblocking(False)
        self.tcp_socks.add(cli_sock)
        self.update_select_socks()
        logger.debug("accept connect: %s", str(cli_sock.getpeername()))

    def process_icmp_sock(self):
        icmp_p = self.recv_icmp()
        # logger.debug("process_icmp: %s", str(icmp_p))
        if not icmp_p:
            return None
        if not self.check_seq(icmp_p):
            logger.debug("check_seq failed: %s", str(icmp_p))
            return None

        if icmp_p.id not in self.id_tunnel_map:
            logger.warn("no tunnel %d", icmp_p.id)
            return None

        tun = self.id_tunnel_map[icmp_p.id]

        if icmp_p.seq != 0:
            logger.debug("recv icmp[%d.%d] %d bytes", icmp_p.id, icmp_p.seq, len(icmp_p.data))

        if icmp_p.seq == tun.recv_seq:
            tun.tcp_send_bufs.append(icmp_p.data)
            while 1:
                next_seq = tun.update_recv_seq()
                if next_seq not in tun.icmp_recv_bufs:
                    break
                data = tun.icmp_recv_bufs[next_seq]
                tun.tcp_send_bufs.append(data)
                del tun.icmp_recv_bufs[next_seq]

        elif icmp_p.seq > tun.recv_seq:
            # TODO: 如果缓存的数据包数量过多就关闭这个连接, 防止内存消耗过多
            tun.icmp_recv_bufs[icmp_p.seq] = icmp_p.data
            logger.debug("cached icmp recv data %d.%d, cached pocket: %d",
                         icmp_p.id, icmp_p.seq, len(tun.icmp_recv_bufs))

        elif icmp_p.seq == 0:
            # logger.debug("recv a ack pocket")
            if icmp_p.data.startswith("/ack"):
                ack_seq = int(icmp_p.data[len("/ack"):])
                if ack_seq in tun.icmp_wait_ack_bufs:
                    del tun.icmp_wait_ack_bufs[ack_seq]
                    logger.debug("tunnel %d ack %d", icmp_p.id, ack_seq)
                    sock = tun.socket
                    if sock in self.blocked_socks and \
                                    len(tun.icmp_wait_ack_bufs) < MAX_BUFS_LEN / 2:
                        self.tcp_socks.add(sock)
                        self.blocked_socks.remove(sock)
                        self.update_select_socks()
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
                tun.closing = 1
            return

        if id_ is None:
            id_ = self.new_id()
            logger.debug("new tunnel: %d", id_)
            self.sock_id_map[sock] = id_
            self.id_tunnel_map[id_] = ClientTunnel(id_, sock, self.peer_host)
        else:
            id_ = self.sock_id_map[sock]

        tun = self.id_tunnel_map[id_]
        tun.icmp_send_bufs[tun.send_seq] = data
        tun.update_send_seq()

    def process_send_bufs(self):
        for id_ in self.id_tunnel_map.keys():
            tun = self.id_tunnel_map[id_]

            # tcp
            if tun.tcp_send_bufs:
                bufs = tun.tcp_send_bufs
                tun.tcp_send_bufs = []
                for data in bufs:
                    if data == "/close":
                        tun.closing = 1
                        continue
                    try:
                        tun.socket.sendall(data)
                    except socket.error, e:
                        if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                            logger.debug("[retry] tunnel %d tcp send", tun.id)
                            tun.tcp_send_bufs.append(data)
                        else:
                            logger.debug("[%d]socket.sendall(): %s", tun.id, e)
                            self.socket_close(tun.socket)

            # icmp
            now_time = time.time()
            for seq in tun.icmp_wait_ack_bufs.keys():
                timeout, data = tun.icmp_wait_ack_bufs[seq]
                if now_time >= timeout:
                    tun.icmp_send_bufs[seq] = data
                    del tun.icmp_wait_ack_bufs[seq]

            now_time = time.time()
            for seq in sorted(tun.icmp_send_bufs.keys()):
                data = tun.icmp_send_bufs[seq]
                logger.debug("send icmp[%d.%d] %d bytes", tun.id, seq, len(data))
                self.send_icmp(tun.peer, tun.id, data, seq)
                tun.icmp_wait_ack_bufs[seq] = (now_time+ACK_TIMEOUT, data)
                del tun.icmp_send_bufs[seq]

            if len(tun.icmp_wait_ack_bufs) > MAX_BUFS_LEN and \
                            tun.socket not in self.blocked_socks:
                logger.debug("tunnel %d blocked", tun.id)
                self.blocked_socks.add(tun.socket)
                self.tcp_socks.remove(tun.socket)
                self.update_select_socks()
                tun.block_timeout = time.time() + BLOCK_TIME

            if tun.socket in self.blocked_socks and time.time() >= tun.block_timeout:
                logger.debug("tunnel %d block timeout", tun.id)
                self.tcp_socks.add(sock)
                self.blocked_socks.remove(sock)
                self.update_select_socks()
                tun.closing = 1

            # 断开
            if tun.closing:
                logger.debug("close tunnel: %d", tun.id)
                sock = tun.socket
                if sock in self.tcp_socks:
                    self.socket_close(sock)
                self.send_icmp(tun.peer, tun.id, "/close")     # 发送断开连接请求
                del self.id_tunnel_map[tun.id]
                self.update_select_socks()

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
                self.process_icmp_sock()

            for sock in [x for x in self.tcp_socks if x in r_socks]:
                self.process_tcp_sock(sock)

            self.process_send_bufs()

if __name__ == "__main__":
    #s = ClientServer("14.17.123.11", 9140)
    #s = ClientServer("usvps.jinxing.me", 9140)
    #s = ClientServer("10.19.190.21", 9140)
    s = ClientServer("121.201.1.110", 9140)
    s.serve_active()
    logging.info("Serving %s", str(s.listen_sock.getsockname()))
    s.serve_forever()
