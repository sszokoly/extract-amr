"""Streaming PCAP and PCAPNG conversion to immutable UDP records."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from os import PathLike
from pathlib import Path
from typing import Any, Callable, Iterator, Optional, Protocol, Union, cast

from scapy.error import Scapy_Exception
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment
from scapy.packet import NoPayload, Packet
from scapy.utils import PcapReader

from .errors import CaptureInputError, ProgressError
from .models import CaptureProvenance, FlowSelector, UdpRecord

CapturePath = Union[str, PathLike]
CaptureSource = Union[CapturePath, Any]


class _CaptureReader(Protocol):
    """Runtime surface of PcapReader that scapy's stubs omit."""

    f: Any

    def __iter__(self) -> Iterator[Packet]: ...
    def close(self) -> None: ...


@dataclass
class _CaptureCounts:
    packet_count: int = 0
    udp_packet_count: int = 0


class CaptureProgress:
    """Validate one capture identity and report bytes consumed across passes."""

    def __init__(
        self,
        path: CapturePath,
        pass_count: int,
        advance: Optional[Callable[[int], None]] = None,
    ) -> None:
        if pass_count < 1:
            raise ValueError("pass_count must be at least 1")
        self.path = Path(path)
        self.pass_count = pass_count
        self._advance = advance
        self._identity = self._preflight(self.path)
        self.size = self._identity.st_size
        self.total_bytes = self.size * pass_count
        self.completed_passes = 0
        self._last_position: Optional[int] = None
        self._pending_completion = 0

    @staticmethod
    def _preflight(path: Path) -> os.stat_result:
        try:
            identity = path.stat()
            if not stat.S_ISREG(identity.st_mode):
                raise CaptureInputError(
                    "progress requires an uncompressed regular capture file",
                    details={"path": str(path)},
                )
            if identity.st_size == 0:
                raise CaptureInputError(
                    "progress is unavailable for an empty capture file",
                    details={"path": str(path)},
                )
            with path.open("rb") as source:
                opened_identity = os.fstat(source.fileno())
                if CaptureProgress._identity_values(opened_identity) != (
                    CaptureProgress._identity_values(identity)
                ):
                    raise CaptureInputError(
                        "capture changed while progress was being prepared",
                        details={"path": str(path)},
                    )
                if source.read(2) == b"\x1f\x8b":
                    raise CaptureInputError(
                        "progress is unavailable for compressed capture files",
                        details={"path": str(path)},
                    )
        except CaptureInputError:
            raise
        except OSError as error:
            raise CaptureInputError(
                f"unable to prepare capture progress for {path}: {error}",
                details={"path": str(path)},
            ) from error
        return identity

    @staticmethod
    def _identity_values(identity: os.stat_result) -> tuple:
        return (
            identity.st_dev,
            identity.st_ino,
            identity.st_size,
            identity.st_mtime_ns,
            identity.st_ctime_ns,
        )

    def _validate_identity(self, identity: os.stat_result) -> None:
        if self._identity_values(identity) != self._identity_values(self._identity):
            raise CaptureInputError(
                "capture changed while progress was being measured",
                details={"path": str(self.path)},
            )

    def start_pass(self, path: CaptureSource, source: Any) -> None:
        if not isinstance(path, (str, PathLike)):
            raise CaptureInputError("progress requires a reopenable capture path")
        if self.completed_passes >= self.pass_count or self._last_position is not None:
            raise CaptureInputError("capture progress received an unexpected extra pass")
        try:
            self._validate_identity(Path(path).stat())
            self._validate_identity(os.fstat(source.fileno()))
        except CaptureInputError:
            raise
        except (AttributeError, OSError, ValueError) as error:
            raise CaptureInputError(
                f"unable to validate capture progress for {path}: {error}",
                details={"path": str(path)},
            ) from error
        self._last_position = 0
        self.observe(source)

    def _position(self, source: Any) -> int:
        if self._last_position is None:
            raise CaptureInputError("capture progress pass has not started")
        try:
            position = source.tell()
        except (AttributeError, OSError, ValueError) as error:
            raise CaptureInputError("capture byte position is unavailable") from error
        if isinstance(position, bool) or not isinstance(position, int):
            raise CaptureInputError("capture byte position is invalid")
        if position < self._last_position or position > self.size:
            raise CaptureInputError("capture byte position is outside the expected file")
        return position

    def _advance_to(self, position: int) -> None:
        if self._last_position is None:
            raise CaptureInputError("capture progress pass has not started")
        delta = position - self._last_position
        self._last_position = position
        if delta and self._advance is not None:
            try:
                self._advance(delta)
            except ProgressError:
                raise
            except Exception as error:
                raise ProgressError("unable to update capture progress") from error

    def observe(self, source: Any) -> None:
        position = self._position(source)
        if position < self.size:
            self._advance_to(position)

    def finish_pass(self, path: CaptureSource, source: Any) -> None:
        position = self._position(source)
        if position != self.size:
            raise CaptureInputError(
                "capture ended before the expected byte position",
                details={"path": str(path)},
            )
        try:
            self._validate_identity(Path(path).stat())
            self._validate_identity(os.fstat(source.fileno()))
        except (AttributeError, OSError, ValueError) as error:
            raise CaptureInputError(
                f"unable to validate completed capture progress for {path}: {error}",
                details={"path": str(path)},
            ) from error
        final_delta = position - (self._last_position or 0)
        if self.completed_passes + 1 == self.pass_count:
            self._last_position = position
            self._pending_completion += final_delta
        else:
            self._advance_to(position)
        self.completed_passes += 1
        self._last_position = None

    def ensure_complete(self) -> None:
        if self.completed_passes != self.pass_count or self._last_position is not None:
            raise CaptureInputError("capture progress did not complete every planned pass")
        if self._pending_completion:
            amount = self._pending_completion
            self._pending_completion = 0
            if self._advance is None:
                return
            try:
                self._advance(amount)
            except ProgressError:
                raise
            except Exception as error:
                raise ProgressError("unable to update capture progress") from error


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
    _progress: Optional[CaptureProgress] = None,
) -> Iterator[UdpRecord]:
    """Stream complete IPv4 or IPv6 UDP datagrams from a capture path."""

    active_selector = selector or FlowSelector()
    source = str(path) if isinstance(path, (str, PathLike)) else _NonClosingSource(path)
    try:
        reader = cast(_CaptureReader, PcapReader(cast(str, source)))
        try:
            if _progress is not None:
                _progress.start_pass(path, reader.f)
            for packet_number, packet in enumerate(reader, start=1):
                if _counts is not None:
                    _counts.packet_count += 1
                if _progress is not None:
                    _progress.observe(reader.f)
                record = _udp_record(packet, packet_number, active_selector)
                if record is not None:
                    if _counts is not None:
                        _counts.udp_packet_count += 1
                    yield record
            if _progress is not None:
                _progress.finish_pass(path, reader.f)
        finally:
            reader.close()
    except (EOFError, OSError, Scapy_Exception, ValueError) as error:
        raise CaptureInputError(
            f"unable to read capture {path}: {error}",
            details={"path": str(path)},
        ) from error
