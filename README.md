# lit4

局域网 ICMP / TCP 快速扫描工具，无需 root。

## 安装

```bash
uv tool install /home/forty-wsl/github/lan-icmp-tcp-49
```

## 用法

```bash
# ICMP 存活扫描
lit4 icmp 192.168.1.0/24

# TCP 端口扫描（支持 80 / 80,443 / 80-90 及混合）
lit4 tcp 192.168.1.0/24 80
lit4 tcp 192.168.1.0/24 80,443
lit4 tcp 192.168.1.0/24 20-25,80,443
```

每发现一台就立即打印一行 IP。
