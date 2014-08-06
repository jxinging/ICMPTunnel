# coding: utf8
__author__ = 'JinXing'

import socket
import time
import errno
from _icmp import ICMPPocket
from config import *


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
        self.update_select_socks()

    def send_icmp(self, peer, id_, data, seq=None, type_=None):
        if seq is None:
            tun = self.id_tunnel_map[id_]
            seq = tun.update_send_seq()
        if type_ is None:
            type_ = self.icmp_type
        ICMPPocket(type_, id_, seq, AUTH_STR+data).sendto(self.icmp_sock, peer)

    def recv_icmp(self):
        icmp_p = ICMPPocket.parse(self.icmp_sock, MAX_POCKET_SIZE)
        # logger.debug("recv icmp: %s", str(icmp_p))
        if not icmp_p.data.startswith(AUTH_STR):
            return None
        icmp_p.data = icmp_p.data[AUTH_STR_LEN:]
        return icmp_p

    def update_select_socks(self):
        socks = list(self.tcp_socks)
        socks.append(self.icmp_sock)
        if self.listen_sock:
            socks.append(self.listen_sock)
        self.select_socks = socks
        return self.select_socks

    def process_recv_icmp(self):
        icmp_p = self.recv_icmp()
        if icmp_p is None:
            return

        tun = self.id_tunnel_map[icmp_p.id]
        msg = tun.process_icmp(icmp_p)
        if not msg:
            return

        if msg.is_ack():
            sock = tun.socket
            if sock in self.blocked_socks and \
                            len(tun.icmp_wait_ack_bufs) < MAX_BUFS_LEN / 2:
                logger.debug("tunnel %d activated", tun.id)
                self.tcp_socks.add(sock)
                self.blocked_socks.remove(sock)
                self.update_select_socks()

        elif msg.is_close():
            if not tun.close_timeout:
                logger.debug("tunnel %d closing", tun.id)
                tun.send_icmp_close()
                tun.close_timeout = time.time() + CLOSE_TIMEOUT
                self.socket_close(tun.socket)

    def process_icmp_bufs(self):
        delete_tun_ids = []     # save resource
        for tun in self.id_tunnel_map.itervalues():
            # wait_bufs timeout
            now_time = time.time()
            for seq in tun.icmp_wait_ack_bufs.keys():
                timeout, data = tun.icmp_wait_ack_bufs[seq]
                if now_time >= timeout:
                    logger.debug("icmp data %d.%d ack timeout", tun.id, seq)
                    tun.icmp_send_bufs[seq] = data
                    del tun.icmp_wait_ack_bufs[seq]

            # send_bufs
            now_time = time.time()
            for seq in sorted(tun.icmp_send_bufs.keys()):
                data = tun.icmp_send_bufs[seq]
                # logger.debug("send icmp[%d.%d] %d bytes", tun.id, seq, len(data))
                tun.send_icmp_data(data, seq)
                tun.icmp_wait_ack_bufs[seq] = (now_time+ACK_TIMEOUT, data)
                del tun.icmp_send_bufs[seq]

            # wait_bufs
            if len(tun.icmp_wait_ack_bufs) > MAX_BUFS_LEN and \
                            tun.socket not in self.blocked_socks:
                logger.debug("tunnel %d blocked", tun.id)
                self.blocked_socks.add(tun.socket)
                self.tcp_socks.remove(tun.socket)
                self.update_select_socks()

            if tun.close_timeout and tun.close_timeout >= time.time():
                logger.debug("tunnel %d closed", tun.id)
                delete_tun_ids.append(tun.id)

        for tun_id in delete_tun_ids:
            del self.id_tunnel_map[tun_id]

    def process_recv_tcp(self, sock):
        data = sock.recv(TCP_BUF_LEN)
        # logger.debug("recv tcp data: %s ...", str(data[:64]))
        tun = None
        if sock in self.sock_id_map:
            tun = self.id_tunnel_map.get(self.sock_id_map[sock], None)

        if not data:
            if tun:
                logger.debug("tunnel %d, tcp socket %s closed", tun.id, sock.getpeername())
            else:
                logger.debug("tcp socket closed: %s", sock.getpeername())
            self.socket_close(sock)
            if tun:
                tun = self.id_tunnel_map[tun.id]
                tun.send_icmp_close()
                tun.close_timeout = time.time() + CLOSE_TIMEOUT
            return

        if not tun:
            logger.error("Can't find bound tunnel: %s", str(sock.getpeername()))
            return

        tun.icmp_send_bufs[tun.send_seq] = data
        tun.update_send_seq()

    def process_tcp_bufs(self):
        for tun in self.id_tunnel_map.itervalues():
            if not tun.tcp_send_bufs:
                continue
            bufs = tun.tcp_send_bufs
            tun.tcp_send_bufs = []
            for data in bufs:
                try:
                    # logger.debug("tunnel %d send data(%d bytes) to %s",
                    #              tun.id, len(data), tun.socket.getpeername())
                    tun.socket.sendall(data)
                    # tun.trans_bytes += len(data)
                    # logger.debug("transfer bytes %d", tun.trans_bytes)
                except socket.error, e:
                    if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                        logger.debug("[retry] tunnel %d tcp send", tun.id)
                        tun.tcp_send_bufs.append(data)
                    else:
                        logger.debug("tunnel %d tcp send error: %s", tun.id, e)
                        self.socket_close(tun.socket)
                        tun.send_icmp_close()
                        tun.close_timeout = time.time() + CLOSE_TIMEOUT

    def check_seq(self, icmp_p):
        return True

    def new_tunnel(self):
        raise NotImplemented

    def serve_active(self):
        pass

    def serve_forever(self, poll_interval):
        raise NotImplemented

if __name__ == "__main__":
    print dir(BaseServer())