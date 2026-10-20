"""ICMP / TCP 扫描实现。ICMP 用 DGRAM socket，无需 root。"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
import struct
import sys
import time
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


def _print_results(results: dict[str, float]) -> None:
    """results: IP -> 毫秒，按 IP 由小到大打印一行一个。"""
    for ip in sorted(results, key=lambda s: int(ipaddress.ip_address(s))):
        print(f"{ip} {results[ip]:.0f}ms", flush=True)


async def icmp_scan(
    targets: list[str], timeout: float = 1.5, idle: float = 0.15
) -> int:
    """对 targets 发 ICMP echo，按 IP 升序打印 `ip 毫秒`。返回数量。"""
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
    sent_at: dict[str, float] = {}
    found: dict[str, float] = {}
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
            if ip not in found and ip in sent_at:
                found[ip] = (loop.time() - sent_at[ip]) * 1000
                last_recv = loop.time()

    recv_task = asyncio.create_task(receiver())
    try:
        packet = _echo_request(ident)
        # 先非阻塞连发；缓冲区满的并发等可写再补发
        pending: list[str] = []
        for ip in targets:
            try:
                sock.sendto(packet, (ip, 0))
                sent_at[ip] = loop.time()
            except BlockingIOError:
                pending.append(ip)
            except OSError:
                pass  # 不可达等，忽略
        if pending:
            queued_at = loop.time()
            for ip in pending:
                sent_at[ip] = queued_at
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
            if found and now - last_recv >= idle:
                break
            await asyncio.sleep(0.02)
    finally:
        recv_task.cancel()
        sock.close()

    _print_results(found)
    return len(found)


async def tcp_scan(
    targets: list[str],
    ports: list[int],
    timeout: float = 0.5,
    concurrency: int = 2048,
) -> int:
    """对每个 (ip, port) 做 TCP connect，开放的按 `ip:端口 毫秒` 打印。返回开放条数。"""
    sem = asyncio.Semaphore(concurrency)
    lock = asyncio.Lock()
    up: dict[tuple[str, int], float] = {}

    async def probe(host: str, port: int) -> None:
        async with sem:
            t0 = time.perf_counter()
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout
                )
            except (OSError, TimeoutError):
                return
            ms = (time.perf_counter() - t0) * 1000
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
            async with lock:
                up[(host, port)] = ms

    await asyncio.gather(*(probe(h, p) for h in targets for p in ports))
    for (ip, port), ms in sorted(
        up.items(), key=lambda kv: (int(ipaddress.ip_address(kv[0][0])), kv[0][1])
    ):
        print(f"{ip}:{port} {ms:.0f}ms", flush=True)
    return len(up)
