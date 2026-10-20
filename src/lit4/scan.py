"""ICMP / TCP 扫描实现。ICMP 用 DGRAM socket，无需 root。"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
import struct
import sys
from collections.abc import Iterable


def expand_targets(items: Iterable[str]) -> list[str]:
    """把 CIDR / 单 IP 展开成 IP 列表。"""
    ips: list[str] = []
    for item in items:
        net = ipaddress.ip_network(item, strict=False)
        if net.version != 4:
            raise SystemExit(f"暂不支持 IPv6: {item}")
        ips.extend(str(h) for h in net.hosts())
    return ips


def parse_ports(spec: str) -> list[int]:
    """解析 `80` / `80,443` / `80-90` 及混合写法，返回有序去重端口表。"""
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            start, end = int(a), int(b)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    result = sorted(p for p in ports if 1 <= p <= 65535)
    if not result:
        raise SystemExit(f"无效端口: {spec!r}")
    return result


def _icmp_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _echo_request(ident: int) -> bytes:
    payload = b"lit4" * 8
    header = struct.pack("!BBHHH", 8, 0, 0, ident, 0)
    csum = _icmp_checksum(header + payload)
    return struct.pack("!BBHHH", 8, 0, csum, ident, 0) + payload


async def icmp_scan(
    targets: list[str], timeout: float = 1.5, idle: float = 0.15
) -> int:
    """对 targets 发 ICMP echo，逐行打印有响应的 IP。返回数量。"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
        sock.bind(("", 0))
    except PermissionError:
        print(
            "无法创建 ICMP socket（需要 net.ipv4.ping_group_range 允许）",
            file=sys.stderr,
        )
        raise SystemExit(1) from None
    sock.setblocking(False)

    loop = asyncio.get_running_loop()
    ident = os.getpid() & 0xFFFF
    seen: set[str] = set()
    last_recv = loop.time()

    async def receiver() -> None:
        nonlocal last_recv
        while True:
            try:
                data, addr = await loop.sock_recvfrom(sock, 2048)
            except OSError:
                return
            # Linux ping socket 会改写 ICMP id，只认 echo reply 即可
            if len(data) < 8 or data[0] != 0:  # 0 = echo reply
                continue
            ip = addr[0]
            if ip not in seen:
                seen.add(ip)
                last_recv = loop.time()
                print(ip, flush=True)

    recv_task = asyncio.create_task(receiver())
    try:
        packet = _echo_request(ident)
        # 先非阻塞连发；缓冲区满的并发等可写再补发
        pending: list[str] = []
        for ip in targets:
            try:
                sock.sendto(packet, (ip, 0))
            except BlockingIOError:
                pending.append(ip)
            except OSError:
                pass  # 不可达等，忽略
        if pending:
            try:
                await asyncio.wait_for(
                    asyncio.gather(
                        *(loop.sock_sendto(sock, packet, (ip, 0)) for ip in pending),
                        return_exceptions=True,
                    ),
                    0.2,
                )
            except TimeoutError:
                pass  # 补发超时就丢掉，不拖慢扫描

        # 有回复后静默 idle 秒即结束，否则等满 timeout
        start = loop.time()
        while True:
            now = loop.time()
            if now - start >= timeout:
                break
            if seen and now - last_recv >= idle:
                break
            await asyncio.sleep(0.02)
    finally:
        recv_task.cancel()
        sock.close()
    return len(seen)


async def tcp_scan(
    targets: list[str],
    ports: list[int],
    timeout: float = 0.5,
    concurrency: int = 2048,
) -> int:
    """对每个 (ip, port) 做 TCP connect，任一端口开放即打印该 IP 一次。返回数量。"""
    sem = asyncio.Semaphore(concurrency)
    lock = asyncio.Lock()
    up: set[str] = set()

    async def probe(host: str, port: int) -> None:
        async with sem:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout
                )
            except OSError, TimeoutError:
                return
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
            async with lock:
                if host not in up:
                    up.add(host)
                    print(host, flush=True)

    await asyncio.gather(*(probe(h, p) for h in targets for p in ports))
    return len(up)
