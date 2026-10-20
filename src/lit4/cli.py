"""lit4 命令行入口。"""

from __future__ import annotations

import argparse
import asyncio

from . import __version__
from .scan import expand_targets, icmp_scan, parse_ports, tcp_scan


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="lit4",
        description="局域网 ICMP/TCP 快速扫描，无需 root",
    )
    parser.add_argument("--version", action="version", version=f"lit4 {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_icmp = sub.add_parser("icmp", help="ICMP 存活扫描，例: lit4 icmp 192.168.1.0/24")
    p_icmp.add_argument("targets", nargs="+", metavar="CIDR")

    p_tcp = sub.add_parser(
        "tcp",
        help="TCP 端口扫描，例: lit4 tcp 192.168.1.0/24 80,443 或 80-90",
    )
    p_tcp.add_argument(
        "items",
        nargs="+",
        metavar="CIDR|PORTS",
        help="一个或多个 CIDR，最后一个参数是端口表",
    )
    p_tcp.add_argument("--timeout", type=float, default=0.5, help="单次连接超时秒数")

    ns = parser.parse_args()

    if ns.cmd == "icmp":
        targets = expand_targets(ns.targets)
        asyncio.run(icmp_scan(targets))
    else:
        *cidrs, port_spec = ns.items
        targets = expand_targets(cidrs)
        ports = parse_ports(port_spec)
        asyncio.run(tcp_scan(targets, ports, timeout=ns.timeout))


if __name__ == "__main__":
    main()
