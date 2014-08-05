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

    def new_tunnel(self, peer, id_, seq, host, port):
        logger.debug("new connection: %s#%d.%d", peer, id_, seq)
        ip = socket.gethostbyname(host)
        sock = socket.create_connection((ip, port))
        sock.setblocking(False)
        self.tcp_socks.add(sock)
        self.update_select_socks()
        self.sock_id_map[sock] = id_
        self.id_tunnel_map[id_] = ServerTunnel(id_, sock, peer)
        return self.id_tunnel_map[id_]

    def check_seq(self, icmp_p):
        if icmp_p.seq % 2 != 0:
            # logger.debug("check_seq() seq no error: %d", icmp_p.seq)
            return False
        return BaseServer.check_seq(self, icmp_p)

    def process_icmp_sock(self):
        icmp_p = self.recv_icmp()
        # logger.debug("process_icmp: %s", str(icmp_p))
        if not icmp_p:
            return None
        if not self.check_seq(icmp_p):
            logger.debug("check_seq failed: %s", str(icmp_p))
            return None

        tun = self.id_tunnel_map.get(icmp_p.id, None)
        if tun is None:
            tun = self.new_tunnel(icmp_p.addr, icmp_p.id, icmp_p.seq,
                                self.target_host, self.target_port)

        if icmp_p.seq != 0:
            logger.debug("recv icmp[%d.%d] %d bytes", icmp_p.id, icmp_p.seq, len(icmp_p.data))

        if icmp_p.seq == tun.recv_seq:
            tun.tcp_send_bufs.append(icmp_p.data)
            while 1:
                next_seq = tun.update_recv_seq()    # 更新 recv_seq
                if next_seq not in tun.icmp_recv_bufs:
                    break
                data = tun.icmp_recv_bufs[next_seq]
                tun.tcp_send_bufs.append(data)
                del tun.icmp_recv_bufs[next_seq]
                tun.recv_seq = next_seq

        elif icmp_p.seq > tun.recv_seq:
            # TODO: 如果缓存的数据包数量过多就关闭这个连接, 防止内存消耗过多
            tun.icmp_recv_bufs[icmp_p.seq] = icmp_p.data
            logger.debug("cached icmp recv data %d.%d, cached pocket: %d",
                         icmp_p.id, icmp_p.seq, len(tun.icmp_recv_bufs))

        elif icmp_p.seq == 0:
            if icmp_p.data.startswith("/ack"):
                ack_seq = int(icmp_p.data[len("/ack"):])
                if icmp_p.id not in self.id_tunnel_map:
                    return None
                if ack_seq in tun.icmp_wait_ack_bufs:
                    del tun.icmp_wait_ack_bufs[ack_seq]
                    logger.debug("tunnel %d ack %d", icmp_p.id, ack_seq)
                    sock = tun.socket
                    if sock in self.blocked_socks and \
                                    len(tun.icmp_wait_ack_bufs) < MAX_BUFS_LEN / 2:
                        self.tcp_socks.add(sock)
                        self.blocked_socks.remove(sock)
                        self.update_select_socks()
                return None

        else:
            logger.info("error pocket seq: %d != %d",
                        icmp_p.seq, tun.recv_seq)
            return None

    def process_tcp_sock(self, sock):
        data = sock.recv(TCP_BUF_LEN)
        # logger.debug("recv tcp data: %s ...", str(data[:64]))
        id_ = self.sock_id_map[sock]
        tun = self.id_tunnel_map[id_]
        if len(data) == 0:
            logger.debug("tcp socket closed: %s", sock.getpeername())
            self.socket_close(sock)
            tun.closing = 1
            return

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
                    if data.startswith("/close"):
                        tun.closing = 1
                        continue
                    try:
                        logger.debug("tunnel %d send data to %s: %s",
                                     tun.id, tun.socket.getpeername(), data)
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
                self.tcp_socks.add(tun.socket)
                self.blocked_socks.remove(tun.socket)
                self.update_select_socks()
                tun.closing = 1

            # TODO: 断开后还需要保存数据一段时间，保证两端状态同步
            if tun.closing:
                logger.debug("close tunnel: %d", tun.id)
                sock = tun.socket
                if sock in self.tcp_socks:
                    self.socket_close(sock)
                self.send_icmp(tun.peer, tun.id, "/close")     # 发送断开连接请求
                del self.id_tunnel_map[tun.id]
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
    # s = Server("127.0.0.1", 80)
    s = Server("usvps.jinxing.me", 80)
    logger.info("ICMP Servicing ...")
    s.serve_forever()
