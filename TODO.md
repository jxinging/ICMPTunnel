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

