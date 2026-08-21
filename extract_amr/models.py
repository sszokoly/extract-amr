"""Immutable configuration records shared by the library and CLI."""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from enum import Enum
from pathlib import Path
from typing import Optional, Tuple


class Codec(str, Enum):
    """Supported speech codecs."""

    AMR = "amr"
    AMR_WB = "amr-wb"


class PayloadMode(str, Enum):
    """Supported RFC 4867 payload modes."""

    OCTET_ALIGNED = "octet-aligned"
    BANDWIDTH_EFFICIENT = "bandwidth-efficient"


class GapPolicy(str, Enum):
    """Policy for inferred missing media intervals."""

    OMIT = "omit"
    NO_DATA = "no-data"


class MalformedPolicy(str, Enum):
    """Policy for malformed packets in a selected flow."""

    SKIP = "skip"
    STRICT = "strict"


@dataclass(frozen=True)
class CaptureProvenance:
    """Location of a record in its source capture."""

    packet_number: Optional[int] = None
    capture_timestamp: Optional[Decimal] = None


@dataclass(frozen=True)
class FlowSelector:
    """Optional directional fields used to select one or more RTP flows."""

    src_address: Optional[str] = None
    dst_address: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    ssrc: Optional[int] = None
    payload_type: Optional[int] = None

    def __post_init__(self) -> None:
        for name, port in (("src_port", self.src_port), ("dst_port", self.dst_port)):
            if port is not None and not 1 <= port <= 65535:
                raise ValueError(f"{name} must be between 1 and 65535")
        if self.ssrc is not None and not 0 <= self.ssrc <= 0xFFFFFFFF:
            raise ValueError("ssrc must be between 0 and 4294967295")
        if self.payload_type is not None and not 0 <= self.payload_type <= 127:
            raise ValueError("payload_type must be between 0 and 127")

    @property
    def is_complete(self) -> bool:
        """Whether all fields in a directional RTP flow key are present."""

        return all(
            value is not None
            for value in (
                self.src_address,
                self.dst_address,
                self.src_port,
                self.dst_port,
                self.ssrc,
                self.payload_type,
            )
        )

    @property
    def is_port_filter(self) -> bool:
        """Whether ports form a broad selector rather than a complete key."""

        has_port = self.src_port is not None or self.dst_port is not None
        return has_port and not self.is_complete

    def matches_endpoints(
        self,
        src_address: str,
        dst_address: str,
        src_port: int,
        dst_port: int,
    ) -> bool:
        """Return whether supplied directional endpoint fields match."""

        return all(
            (
                self.src_address is None or self.src_address == src_address,
                self.dst_address is None or self.dst_address == dst_address,
                self.src_port is None or self.src_port == src_port,
                self.dst_port is None or self.dst_port == dst_port,
            )
        )

    def matches_udp(self, record: "UdpRecord") -> bool:
        """Return whether a UDP record matches directional endpoints."""

        return self.matches_endpoints(
            record.src_address,
            record.dst_address,
            record.src_port,
            record.dst_port,
        )

    def matches_flow(self, key: "FlowKey") -> bool:
        """Return whether a complete RTP flow matches every supplied field."""

        return all(
            (
                self.matches_endpoints(
                    key.src_address,
                    key.dst_address,
                    key.src_port,
                    key.dst_port,
                ),
                self.ssrc is None or self.ssrc == key.ssrc,
                self.payload_type is None or self.payload_type == key.payload_type,
            )
        )


@dataclass(frozen=True)
class UdpRecord:
    """One captured, complete, non-fragmented UDP datagram."""

    src_address: str
    dst_address: str
    src_port: int
    dst_port: int
    payload: bytes
    ip_version: int
    provenance: CaptureProvenance


@dataclass(frozen=True)
class FlowKey:
    """Complete identity of one directional RTP flow."""

    src_address: str
    dst_address: str
    src_port: int
    dst_port: int
    ssrc: int
    payload_type: int


@dataclass(frozen=True)
class RtpRecord:
    """Validated RTP header metadata and normalized media payload."""

    flow_key: FlowKey
    sequence: int
    timestamp: int
    marker: bool
    payload: bytes
    provenance: CaptureProvenance
    csrcs: Tuple[int, ...] = ()
    extension_profile: Optional[int] = None
    extension_data: bytes = b""
    padding_length: int = 0


@dataclass(frozen=True)
class EncodedFrame:
    """One normalized AMR or AMR-WB frame independent of storage output."""

    codec: Codec
    frame_type: int
    quality: bool
    bit_length: int
    data: bytes
    media_timestamp: int
    provenance: CaptureProvenance


@dataclass(frozen=True)
class Rfc4867Options:
    """Negotiated RFC 4867 options relevant to payload interpretation."""

    channels: int = 1
    crc: bool = False
    interleaving: bool = False
    robust_sorting: bool = False

    def __post_init__(self) -> None:
        if self.channels < 1:
            raise ValueError("channels must be at least 1")


@dataclass(frozen=True)
class PayloadProbe:
    """Exact validation result for one payload and codec/mode pair."""

    codec: Codec
    payload_mode: PayloadMode
    success: bool
    frame_count: int = 0
    rejection_reason: Optional[str] = None
    rejection_message: Optional[str] = None


@dataclass(frozen=True)
class FormatEvidence:
    """Aggregate exact-probe evidence for one flow format."""

    codec: Codec
    payload_mode: PayloadMode
    success_count: int
    failure_count: int
    first_rejection_reason: Optional[str] = None

    @property
    def is_valid(self) -> bool:
        """Whether every sampled payload validated in this format."""

        return self.success_count > 0 and self.failure_count == 0


@dataclass(frozen=True)
class ProbeDiagnostic:
    """One retained codec-probe rejection with capture provenance."""

    candidate_id: str
    codec: Codec
    payload_mode: PayloadMode
    reason: str
    message: str
    provenance: CaptureProvenance


@dataclass(frozen=True)
class FlowCandidate:
    """One bounded directional RTP flow and its format evidence."""

    candidate_id: str
    flow_key: FlowKey
    first_packet_number: int
    sampled_packet_count: int
    sample_overflow_count: int
    formats: Tuple[FormatEvidence, ...]

    @property
    def valid_formats(self) -> Tuple[FormatEvidence, ...]:
        """Return formats supported consistently by sampled payloads."""

        return tuple(evidence for evidence in self.formats if evidence.is_valid)


@dataclass(frozen=True)
class SelectedFlow:
    """A full flow with one resolved codec and payload mode."""

    candidate_id: str
    flow_key: FlowKey
    codec: Codec
    payload_mode: PayloadMode
    first_packet_number: int


@dataclass(frozen=True)
class DiscoveryResult:
    """Bounded evidence; overflow counts summarize discarded observations."""

    candidates: Tuple[FlowCandidate, ...]
    diagnostics: Tuple[ProbeDiagnostic, ...]
    observed_packet_count: int
    sampled_packet_count: int
    candidate_overflow_count: int = 0
    sample_overflow_count: int = 0
    diagnostic_overflow_count: int = 0

    @property
    def valid_candidates(self) -> Tuple[FlowCandidate, ...]:
        """Return candidates having at least one consistent format."""

        return tuple(candidate for candidate in self.candidates if candidate.valid_formats)


@dataclass(frozen=True)
class TimelineDiagnostic:
    """One retained timeline event tied to capture provenance."""

    reason: str
    message: str
    provenance: CaptureProvenance


@dataclass(frozen=True)
class TimelineSummary:
    """Immutable statistics for one normalized directional flow."""

    flow_key: FlowKey
    codec: Codec
    payload_mode: PayloadMode
    packet_count: int
    accepted_packet_count: int
    observed_frame_count: int
    emitted_frame_count: int
    bad_quality_frame_count: int
    malformed_packet_count: int
    duplicate_packet_count: int
    reordered_packet_count: int
    late_packet_count: int
    overlap_frame_count: int
    gap_count: int
    inserted_no_data_count: int
    packet_history_overflow_count: int
    highest_extended_sequence: Optional[int]
    highest_extended_timestamp: Optional[int]
    diagnostics: Tuple[TimelineDiagnostic, ...]
    diagnostic_overflow_count: int = 0


@dataclass(frozen=True)
class RoutedFrame:
    """A normalized frame tagged with its independent full flow key."""

    flow_key: FlowKey
    frame: EncodedFrame


@dataclass(frozen=True)
class InspectionReport:
    """Bounded capture inspection candidates and statistics."""

    discovery: DiscoveryResult
    capture_packet_count: int
    udp_packet_count: int
    rtp_packet_count: int
    malformed_rtp_count: int
    diagnostics: Tuple[TimelineDiagnostic, ...]
    diagnostic_overflow_count: int = 0

    @property
    def candidates(self) -> Tuple[FlowCandidate, ...]:
        return self.discovery.candidates

    @property
    def valid_candidates(self) -> Tuple[FlowCandidate, ...]:
        return self.discovery.valid_candidates


@dataclass(frozen=True)
class ExtractionReport:
    """Complete result for one independently extracted full flow."""

    selected_flow: SelectedFlow
    output_path: Optional[Path]
    bit_backend: str
    bit_backend_fallback_reason: Optional[str]
    capture_pass_count: int
    capture_packet_count: int
    udp_packet_count: int
    selected_rtp_packet_count: int
    emitted_frame_count: int
    bad_quality_frame_count: int
    duplicate_packet_count: int
    gap_count: int
    inserted_no_data_count: int
    reordered_packet_count: int
    late_packet_count: int
    overlap_frame_count: int
    malformed_packet_count: int
    packet_history_overflow_count: int
    diagnostics: Tuple[TimelineDiagnostic, ...]
    diagnostic_overflow_count: int = 0


@dataclass(frozen=True)
class ResourceLimits:
    """Bounds for state retained while inspecting or extracting a capture."""

    max_candidates: int = 1024
    max_samples_per_flow: int = 64
    max_diagnostics: int = 100
    reorder_window: int = 64

    def __post_init__(self) -> None:
        if self.max_diagnostics < 0:
            raise ValueError("max_diagnostics must be at least 0")
        for name, value in (
            ("max_candidates", self.max_candidates),
            ("max_samples_per_flow", self.max_samples_per_flow),
            ("reorder_window", self.reorder_window),
        ):
            if value < 1:
                raise ValueError(f"{name} must be at least 1")


@dataclass(frozen=True)
class InspectOptions:
    """Validated options for capture inspection."""

    input_path: Path
    selector: FlowSelector = field(default_factory=FlowSelector)
    codec: Optional[Codec] = None
    payload_mode: Optional[PayloadMode] = None
    limits: ResourceLimits = field(default_factory=ResourceLimits)
    progress: bool = False
    report_all: bool = False


@dataclass(frozen=True)
class ExtractOptions:
    """Validated options for one extraction request."""

    input_path: Path
    output_path: Optional[Path] = None
    output_dir: Optional[Path] = None
    selector: FlowSelector = field(default_factory=FlowSelector)
    codec: Optional[Codec] = None
    payload_mode: Optional[PayloadMode] = None
    gap_policy: GapPolicy = GapPolicy.OMIT
    malformed_policy: MalformedPolicy = MalformedPolicy.SKIP
    limits: ResourceLimits = field(default_factory=ResourceLimits)
    progress: bool = False

    def __post_init__(self) -> None:
        if (self.output_path is None) == (self.output_dir is None):
            raise ValueError("provide exactly one of output_path or output_dir")
        if self.selector.is_port_filter and self.output_dir is None:
            raise ValueError("a UDP-port filter requires output_dir")
        if not self.selector.is_port_filter and self.output_path is None:
            raise ValueError("single-flow extraction requires output_path")
