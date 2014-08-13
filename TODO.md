# 原理
- local 监听一个 tcp 端口
- 把所有从这个端口接收的数据传输到 remote, remote 根据数据中的 tip:tport 建立连接
- 发数据

# TODO:
1. socket 连接异常处理
2. 分析优化网络极差情况
3. 保活超时机制
4. 节省CPU占用(checksum, struct)
5. icmp type hack
6. icmp_send_bufs 改成 list
7. 异步建立　TCP　连接
8. 批量确认，确认重传 **

9. 整理 tun.closing 等状态的管理， 统一接口化, 发送接收数据前先检查 socket 状态
10. 自动 ack timeout 调节
11. 第一个建立连接的包超时后就断开连接, 加快连接不成功时的返回速度

12. 通过统计各种数值，分析、优化
13. 关闭连接时还有数据未发送的处理(有丢包，一直得不到重传)