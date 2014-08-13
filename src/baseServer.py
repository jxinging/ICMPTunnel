# coding: utf8
__author__ = 'JinXing'

import socket
import time
import errno
from message import Message
from _icmp import ICMPPocket
from config import *


class BaseServer(object):
    def __init__(self):
        self.icmp_sock = None
        self.listen_sock = None

        self.sock_id_map = {}
        self.id_tunnel_map = {}

        self.tcp_socks = set()

        self.select_socks = None
        self.icmp_type = None

    def socket_close(self, sock):
        try:
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()
        except socket.error, e:
            logger.warn("close socket error: %s", e)

        if sock in self.tcp_socks:
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
        if not icmp_p or not icmp_p.data.startswith(AUTH_STR):
            return None
        icmp_p.data = icmp_p.data[AUTH_STR_LEN:]
        return icmp_p

    def recv_tcp(self, sock, tun):
        """接收并分析数据确定最终的连接到的 IP:PORT"""
        host = port = None
        return sock.recv(TCP_BUF_LEN), host, port

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

        msg = Message.decode(icmp_p.data)
        # TODO: 下面这段应该放到 server.py
        if msg.is_connect():
            if icmp_p.id in self.id_tunnel_map:
                # logger.debug("recv create connection message by id %d, but it is existed", icmp_p.id)
                return

            try:
                if msg.data.find(":") > 0:
                    host, port = msg.data.split(":")
                    port = int(port)
                else:
                    host, port = self.target_host, self.target_port
                self.new_tunnel(icmp_p.addr, icmp_p.id, host, port)
            except Exception, e:
                logger.error("create new tunnel failed: %s", e)
                import traceback
                traceback.print_exc()
                return None

        if icmp_p.id not in self.id_tunnel_map:
            # logger.debug("recv message: %s, but tunnel %d not exist", str(msg), icmp_p.id)
            return

        tun = self.id_tunnel_map[icmp_p.id]

        # tun.process_icmp() 会改动 icmp_wait_ack_bufs 所以这里先取出最小 seq
        min_wait_ack_seq = None
        if tun.icmp_wait_ack_bufs:
            min_wait_ack_seq = min(tun.icmp_wait_ack_bufs.keys())
        msg = tun.process_icmp(icmp_p, msg)
        if not msg:
            return

        if msg.is_ack():
            if tun.blocked:
                # logger.debug("wait ack pockets: %s", tun.icmp_wait_ack_bufs.keys())
                # 最小seq的包以及一半的包都收到了 ack 才重新启用 tunnel
                if min_wait_ack_seq not in tun.icmp_wait_ack_bufs:  # and \
                # if len(tun.icmp_wait_ack_bufs) < MAX_WAIT_ACK_POCKETS/2:
                    logger.info("******** tunnel %d activated", tun.id)
                    tun.blocked = False
                    if not tun.socket_closed:
                        self.tcp_socks.add(tun.socket)
                    self.update_select_socks()

        elif msg.is_close():
            if not tun.closing:
                logger.info("recv tunnel close message, tunnel %d closing", tun.id)
                tun.closing = True
                # self.socket_close(tun.socket)

    def process_icmp_bufs(self):
        delete_tun_ids = []     # save resource
        for tun in self.id_tunnel_map.itervalues():

            if tun.check_send_ack_timeout():
                tun.send_icmp_ack()

            # wait_bufs timeout
            now_time = time.time()
            for seq in tun.icmp_wait_ack_bufs.keys():
                timeout, data = tun.icmp_wait_ack_bufs[seq]
                if not tun.closing and timeout != 0 and now_time >= timeout:
                    logger.debug("icmp data %d.%d ack timeout", tun.id, seq)
                    tun.retry_count += 1
                    tun.send_icmp_data(data, seq)
                    tun.icmp_wait_ack_bufs[seq] = (now_time+ACK_TIMEOUT, data)

            # send_bufs
            if not tun.blocked:
                now_time = time.time()
                for seq in sorted(tun.icmp_send_bufs.keys()):
                    data = tun.icmp_send_bufs[seq]
                    logger.debug("send icmp[%d.%d] %d bytes", tun.id, seq, len(data))
                    tun.send_icmp_data(data, seq)
                    tun.icmp_wait_ack_bufs[seq] = (now_time+ACK_TIMEOUT, data)
                    del tun.icmp_send_bufs[seq]

                    if len(tun.icmp_wait_ack_bufs) >= MAX_WAIT_ACK_POCKETS:
                        logger.info("******** tunnel %d blocked", tun.id)
                        tun.blocked = True
                        break

                    # break   # 一次只发一个包

                if tun.blocked and tun.socket in self.tcp_socks:
                        self.tcp_socks.remove(tun.socket)
                        self.update_select_socks()

            # keepalive
            now_time = time.time()
            if now_time - tun.last_live >= KEEPALIVE_TIMEOUT:
                if not tun.closing:
                    logger.debug("tunnel %d keepalive timeout, close it", tun.id)
                    tun.closing = True
                if not tun.close_timeout:
                    if tun.recv_seq == 0:   # 对方没有返回过任何包，不进行关闭超时等待
                        timeout = time.time()
                    else:
                        timeout = time.time() + CLOSE_TIMEOUT
                    tun.close_timeout = timeout   # keepalive 超时后不管队列中是否有数据都关闭连接
                    tun.send_icmp_close()
            elif now_time - tun.last_live >= KEEPALIVE_TIMEOUT / 2.0:
                tun.send_icmp_keepalive()

            if tun.closing and not tun.icmp_send_bufs and not tun.tcp_send_bufs:
                if tun.close_timeout == 0:
                    tun.close_timeout = time.time()+CLOSE_TIMEOUT

            if tun.closing and tun.close_timeout != 0 and tun.close_timeout <= time.time():
                # logger.debug("close timeout: %f, now time: %f", tun.close_timeout, time.time())
                tun.send_icmp_ack(None, False)  # 强制发送 ack 包
                logger.info("tunnel %d closed", tun.id)
                if not tun.socket_closed:
                    tun.socket_closed = True
                    self.socket_close(tun.socket)
                delete_tun_ids.append(tun.id)

        # delete tunnel
        for tun_id in delete_tun_ids:
            tun = self.id_tunnel_map[tun_id]
            logger.info("tunnel %d send bytes: %d, send count: %d, "
                        "send data count: %d, retry count: %d",
                        tun.id, tun.trans_bytes, tun.send_count, tun.data_send_count, tun.retry_count)
            del self.id_tunnel_map[tun_id]

        if delete_tun_ids:
            logger.info("connecting tunnels %d", len(self.id_tunnel_map))

    def process_recv_tcp(self, sock):
        tun = None
        if sock in self.sock_id_map:
            tun = self.id_tunnel_map.get(self.sock_id_map[sock], None)

        try:
            data, target_ip, target_port = self.recv_tcp(sock, tun)
            # logger.debug("recv tcp data: %s ...", str(data[:64]))
        except socket.error, e:
            if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                # logger.debug("[retry] tunnel %d tcp send", tun.id)
                # if data and tun:
                #     tun.icmp_send_bufs.append(data)
                if not tun:
                    logger.debug("no tunnel but recv EAGAIN, close it")
                    self.socket_close(sock)
                    return
            else:
                if tun:
                    logger.error("tunnel %d tcp recv error: %s", tun.id, e)
                    tun.send_icmp_close()
                    tun.closing = True
                    if not tun.socket_closed:
                        tun.socket_closed = True
                        self.socket_close(sock)
                else:
                    logger.error("tcp recv error: %s", e)
                    self.socket_close(sock)
                return

        if not data:
            try:
                sock_info = sock.getpeername()
            except socket.error, _:
                sock_info = ""
            if tun:
                logger.info("tunnel %d, tcp socket %s closed. send tunnel close message", tun.id, sock_info)
                tun = self.id_tunnel_map[tun.id]
                tun.send_icmp_close()
                if not tun.close_timeout:
                    # tun.closing = True
                    tun.close_timeout = time.time() + CLOSE_TIMEOUT
                if not tun.socket_closed:
                    tun.socket_closed = True
                    self.socket_close(sock)
            else:
                logger.info("tcp socket closed: %s", sock_info)
                self.socket_close(sock)
            return

        if not tun:
            tun_id = self.new_id()
            try:
                tun = self.new_tunnel(sock, tun_id, target_ip, target_port)
            except Exception, e:
                logger.error("create new tunnel failed: %s", e)
                import traceback
                traceback.print_exc()
                self.socket_close(sock)
                return

        if not tun:
            logger.error("Can't find bound tunnel: %s", str(sock.getpeername()))
            return

        # logger.debug("ready send data %d.%d", tun.id, tun.send_seq)
        tun.icmp_send_bufs[tun.send_seq] = data
        tun.update_send_seq()

    def process_tcp_bufs(self):
        for tun in self.id_tunnel_map.itervalues():
            if not tun.tcp_send_bufs:
                continue
            if tun.socket_closed:
                tun.tcp_send_bufs = []
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
                        logger.debug("tunnel %d tcp send error: resource busy", tun.id)
                    else:
                        logger.error("tunnel %d tcp send error: %s", tun.id, e)
                        if not tun.socket_closed:
                            self.socket_close(tun.socket)
                            tun.socket_closed = True
                        tun.send_icmp_close()
                        tun.closing = True

                    break   # 一旦出错就退出发送循环

    def new_id(self):
        raise NotImplemented

    def new_tunnel(self):
        raise NotImplemented

    def serve_active(self):
        pass

    def serve_forever(self, poll_interval):
        raise NotImplemented

if __name__ == "__main__":
    print dir(BaseServer())