"""Streaming PCAP and PCAPNG conversion to immutable UDP records."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from os import PathLike
from typing import Any, Iterator, Optional, Union

from scapy.error import Scapy_Exception
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment
from scapy.packet import NoPayload, Packet
from scapy.utils import PcapReader

from .errors import CaptureInputError
from .models import CaptureProvenance, FlowSelector, UdpRecord

CapturePath = Union[str, PathLike]
CaptureSource = Union[CapturePath, Any]


@dataclass
class _CaptureCounts:
    packet_count: int = 0
    udp_packet_count: int = 0


class _NonClosingSource:
    def __init__(self, source: Any) -> None:
        self._source = source

    def close(self) -> None:
        pass

    def __getattr__(self, name: str) -> Any:
        return getattr(self._source, name)


def _outer_network_layer(packet: Packet) -> Optional[Packet]:
    current = packet
    while not isinstance(current, NoPayload):
        if isinstance(current, (IP, IPv6)):
            return current
        current = current.payload
    return None


def _udp_layer(network: Packet) -> Optional[UDP]:
    if isinstance(network, IP) and (int(network.frag) != 0 or bool(network.flags.MF)):
        return None

    current = network.payload
    while not isinstance(current, NoPayload):
        if isinstance(current, IPv6ExtHdrFragment):
            return None
        if isinstance(current, UDP):
            return current
        if isinstance(current, (IP, IPv6)):
            return None
        current = current.payload
    return None


def _capture_timestamp(packet: Packet) -> Optional[Decimal]:
    timestamp = getattr(packet, "time", None)
    if timestamp is None:
        return None
    try:
        return Decimal(str(timestamp))
    except (InvalidOperation, ValueError):
        return None


def _udp_payload(udp: UDP) -> Optional[bytes]:
    if udp.len is None:
        return None
    declared_length = int(udp.len)
    captured = bytes(udp.original)
    if declared_length < 8 or len(captured) < declared_length:
        return None
    return captured[8:declared_length]


def _udp_record(
    packet: Packet,
    packet_number: int,
    selector: FlowSelector,
) -> Optional[UdpRecord]:
    network = _outer_network_layer(packet)
    if network is None:
        return None
    udp = _udp_layer(network)
    if udp is None:
        return None

    src_address = str(network.src)
    dst_address = str(network.dst)
    src_port = int(udp.sport)
    dst_port = int(udp.dport)
    if not selector.matches_endpoints(
        src_address,
        dst_address,
        src_port,
        dst_port,
    ):
        return None

    payload = _udp_payload(udp)
    if payload is None:
        return None
    return UdpRecord(
        src_address=src_address,
        dst_address=dst_address,
        src_port=src_port,
        dst_port=dst_port,
        payload=payload,
        ip_version=int(network.version),
        provenance=CaptureProvenance(
            packet_number=packet_number,
            capture_timestamp=_capture_timestamp(packet),
        ),
    )


def iter_udp_records(
    path: CaptureSource,
    selector: Optional[FlowSelector] = None,
    *,
    _counts: Optional[_CaptureCounts] = None,
) -> Iterator[UdpRecord]:
    """Stream complete IPv4 or IPv6 UDP datagrams from a capture path."""

    active_selector = selector or FlowSelector()
    source = str(path) if isinstance(path, (str, PathLike)) else _NonClosingSource(path)
    try:
        with PcapReader(source) as reader:
            for packet_number, packet in enumerate(reader, start=1):
                if _counts is not None:
                    _counts.packet_count += 1
                record = _udp_record(packet, packet_number, active_selector)
                if record is not None:
                    if _counts is not None:
                        _counts.udp_packet_count += 1
                    yield record
    except (EOFError, OSError, Scapy_Exception, ValueError) as error:
        raise CaptureInputError(
            f"unable to read capture {path}: {error}",
            details={"path": str(path)},
        ) from error
