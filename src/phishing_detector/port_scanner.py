"""Basic TCP port scanning utilities."""

from __future__ import annotations

from dataclasses import dataclass
import socket
from typing import Iterable


@dataclass
class PortScanResult:
    host: str
    open_ports: list[int]
    closed_ports: list[int]
    timeout: float


def scan_ports(host: str, ports: Iterable[int], timeout: float = 0.5) -> PortScanResult:
    open_ports: list[int] = []
    closed_ports: list[int] = []

    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                open_ports.append(port)
        except OSError:
            closed_ports.append(port)

    return PortScanResult(
        host=host,
        open_ports=sorted(open_ports),
        closed_ports=sorted(closed_ports),
        timeout=timeout,
    )


def parse_ports(ports_spec: str) -> list[int]:
    if not ports_spec.strip():
        raise ValueError("Ports cannot be empty.")

    ports: set[int] = set()
    for chunk in ports_spec.split(","):
        token = chunk.strip()
        if not token:
            continue
        if "-" in token:
            start_str, end_str = (part.strip() for part in token.split("-", 1))
            if not start_str or not end_str:
                raise ValueError(f"Invalid port range '{token}'.")
            start = _parse_port(start_str)
            end = _parse_port(end_str)
            if start > end:
                raise ValueError(f"Port range start '{start}' must be <= end '{end}'.")
            ports.update(range(start, end + 1))
        else:
            ports.add(_parse_port(token))

    if not ports:
        raise ValueError("No valid ports provided.")

    return sorted(ports)


def _parse_port(value: str) -> int:
    if not value.isdigit():
        raise ValueError(f"Invalid port '{value}'.")
    port = int(value)
    if not 1 <= port <= 65535:
        raise ValueError(f"Port '{port}' must be between 1 and 65535.")
    return port
