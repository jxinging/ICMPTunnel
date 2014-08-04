# coding: utf8
__author__ = 'JinXing'

import socket
import select
import time
from config import *
from tunnel import ServerTunnel
from baseServer import BaseServer


class Server(BaseServer):
    def __init__(self, target_host, target_port):
        BaseServer.__init__(self)
        self.target_host = target_host
        self.target_port = target_port
        self.icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                      socket.getprotobyname("icmp"))

    def new_tunnel(self, peer, id_, seq, host, port):
        logger.debug("new connection: %s#%d.%d", peer, id_, seq)
        ip = socket.gethostbyname(host)
        sock = socket.create_connection((ip, port))
        sock.setblocking(False)
        self.conn_socks.add(sock)
        self.sock_id_map[sock] = id_
        self.id_tunnel_map[id_] = ServerTunnel(id_, sock, peer)
        return self.id_tunnel_map[id_]

    def check_seq(self, icmp_p):
        if icmp_p.seq % 2 != 0:
            return False
        return BaseServer.check_seq(self, icmp_p)

    def process_icmp_sock(self):
        icmp_p = self.recv_icmp()
        if not icmp_p or not self.check_seq(icmp_p):
            return

        tun = self.id_tunnel_map.get(icmp_p.id, None)
        if tun is None:
            tun = self.new_tunnel(icmp_p.addr, icmp_p.id, icmp_p.seq,
                                self.target_host, self.target_port)

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
        # logger.debug("recv tcp data: %s", data)
        id_ = self.sock_id_map[sock]
        tun = self.id_tunnel_map[id_]
        if len(data) == 0:
            logger.debug("tcp socket closed: %s", sock.getpeername())
            self.socket_close(sock)
            tun.closing = 1
            return

        tun.icmp_send_bufs[tun.next_send_seq()] = data

    def process_send_bufs(self):
        for id_ in self.id_tunnel_map.keys():
            tun = self.id_tunnel_map[id_]

            # tcp
            if tun.tcp_send_bufs:
                bufs = tun.tcp_send_bufs
                tun.tcp_send_bufs = []
                for data in bufs:
                    if data.startswith("/close"):
                        tun.closing = 1
                        continue
                    try:
                        logger.debug("tunnel %d send data: %s", id_, data)
                        tun.socket.sendall(data)
                    except socket.error, e:
                        if e.errno in (socket.EAGAIN, socket.EWOULDBLOCK):
                            tun.tcp_send_bufs.append(data)
                        else:
                            logger.debug("[%d]socket.sendall(): %s", tun.id, e)
                            self.socket_close(tun.socket)
            # icmp
            for seq in sorted(tun.icmp_send_bufs.keys()):
                data = tun.icmp_send_bufs[seq]
                logger.debug("send icmp[%d] %db", id_, len(data))
                self.send_icmp(tun.peer, id_, data, seq)

            if len(tun.icmp_send_bufs) > MAX_BUFS_LEN and \
                            tun.socket not in self.blocked_socks:
                self.blocked_socks.add(tun.socket)
                self.tcp_socks.remove(tun.socket)
                self.update_select_socks()
                tun.block_timeout = time.time() + BLOCK_TIME
                logger.debug("tunnel %d blocked", id_)

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

            if tun.closing:
                logger.debug("close tunnel: %d", id_)
                sock = tun.socket
                if sock in self.tcp_socks:
                    self.socket_close(sock)
                self.send_icmp(tun.peer, id_, "/close")     # 发送断开连接请求
                del self.id_tunnel_map[id_]
                self.update_select_socks()

    def serve_forever(self, poll_interval=0.01):
        self.update_select_socks()
        empty_list = ()
        while 1:
            r_socks, _, _ = select.select(self.select_socks,
                                          empty_list, empty_list, poll_interval)

            if self.icmp_sock in r_socks:
                self.process_icmp_sock()

            for sock in [x for x in self.tcp_socks if x in r_socks]:
                self.process_tcp_sock(sock)

            self.process_send_bufs()

if __name__ == "__main__":
    s = Server("14.17.123.11", 80)
    logger.debug("ICMP Servicing ...")
    s.serve_forever()