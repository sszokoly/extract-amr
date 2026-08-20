"""Bounded per-flow RTP timeline normalization."""

from __future__ import annotations

from collections import deque
from decimal import Decimal
from itertools import chain
from typing import Deque, Dict, Iterable, Iterator, Optional, Set, Tuple

from .codec import codec_definition
from .errors import Rfc4867Error
from .models import (
    CaptureProvenance,
    Codec,
    EncodedFrame,
    FlowKey,
    GapPolicy,
    PayloadMode,
    ResourceLimits,
    RoutedFrame,
    RtpRecord,
    SelectedFlow,
    TimelineDiagnostic,
    TimelineSummary,
)
from .rfc4867 import depacketize


def _extend_wrapping(value: int, reference: Optional[int], bits: int) -> int:
    """Map an unsigned wrapping value to the cycle nearest a reference."""

    if reference is None:
        return value
    modulus = 1 << bits
    half = modulus >> 1
    candidate = (reference & ~(modulus - 1)) | value
    if candidate - reference > half:
        candidate -= modulus
    elif reference - candidate > half:
        candidate += modulus
    return candidate


def _provenance_key(provenance: CaptureProvenance) -> tuple:
    timestamp = provenance.capture_timestamp
    if provenance.packet_number is not None:
        return (
            0,
            provenance.packet_number,
            timestamp if timestamp is not None else Decimal("Infinity"),
        )
    return (
        1,
        timestamp if timestamp is not None else Decimal("Infinity"),
    )


def _prefer_frame(candidate: EncodedFrame, current: EncodedFrame) -> bool:
    if candidate.quality != current.quality:
        return candidate.quality
    if candidate.bit_length != current.bit_length:
        return candidate.bit_length > current.bit_length
    return _provenance_key(candidate.provenance) < _provenance_key(current.provenance)


def _route_frames(
    flow_key: FlowKey,
    frames: Iterable[EncodedFrame],
) -> Iterator[RoutedFrame]:
    return (RoutedFrame(flow_key=flow_key, frame=frame) for frame in frames)


class TimelineNormalizer:
    """Normalize one flow; each output iterator must be consumed in order."""

    def __init__(
        self,
        flow_key: FlowKey,
        codec: Codec,
        payload_mode: PayloadMode,
        *,
        gap_policy: GapPolicy = GapPolicy.OMIT,
        limits: Optional[ResourceLimits] = None,
    ) -> None:
        self.flow_key = flow_key
        self.codec = codec
        self.payload_mode = payload_mode
        self.gap_policy = gap_policy
        self.limits = limits or ResourceLimits()
        self._definition = codec_definition(codec)
        self._pending: Dict[int, EncodedFrame] = {}
        self._recent_packet_order: Deque[Tuple[tuple, int]] = deque()
        self._recent_packets: Set[tuple] = set()
        self._packet_history_limit = max(4, self.limits.reorder_window * 4)
        self._highest_sequence: Optional[int] = None
        self._highest_timestamp: Optional[int] = None
        self._last_committed_timestamp: Optional[int] = None
        self._packet_count = 0
        self._accepted_packet_count = 0
        self._observed_frame_count = 0
        self._emitted_frame_count = 0
        self._bad_quality_frame_count = 0
        self._malformed_packet_count = 0
        self._duplicate_packet_count = 0
        self._reordered_packet_count = 0
        self._late_packet_count = 0
        self._overlap_frame_count = 0
        self._gap_count = 0
        self._inserted_no_data_count = 0
        self._packet_history_overflow_count = 0
        self._diagnostics = []
        self._diagnostic_overflow_count = 0
        self._output_pending = False
        self._finished = False

    def _retain_diagnostic(
        self,
        reason: str,
        message: str,
        provenance: CaptureProvenance,
    ) -> None:
        if len(self._diagnostics) < self.limits.max_diagnostics:
            self._diagnostics.append(
                TimelineDiagnostic(
                    reason=reason,
                    message=message,
                    provenance=provenance,
                ),
            )
        else:
            self._diagnostic_overflow_count += 1

    def _packet_identity(self, record: RtpRecord, extended_sequence: int) -> tuple:
        return (
            extended_sequence,
            record.timestamp,
            record.marker,
            record.payload,
            record.csrcs,
            record.extension_profile,
            record.extension_data,
            record.padding_length,
        )

    def _evict_committed_packet_identities(self) -> None:
        if self._last_committed_timestamp is None:
            return
        retained = deque(
            (identity, timestamp)
            for identity, timestamp in self._recent_packet_order
            if timestamp > self._last_committed_timestamp
        )
        self._recent_packet_order = retained
        self._recent_packets = {identity for identity, _ in retained}

    def _retain_packet_identity(self, identity: tuple, timestamp: int) -> bool:
        self._evict_committed_packet_identities()
        if len(self._recent_packet_order) >= self._packet_history_limit:
            return False
        self._recent_packet_order.append((identity, timestamp))
        self._recent_packets.add(identity)
        return True

    def _add_frames(self, frames: Iterable[EncodedFrame]) -> bool:
        had_late_frame = False
        for frame in frames:
            self._observed_frame_count += 1
            if (
                self._last_committed_timestamp is not None
                and frame.media_timestamp <= self._last_committed_timestamp
            ):
                had_late_frame = True
                continue
            current = self._pending.get(frame.media_timestamp)
            if current is None:
                self._pending[frame.media_timestamp] = frame
                continue
            self._overlap_frame_count += 1
            if _prefer_frame(frame, current):
                self._pending[frame.media_timestamp] = frame
        return had_late_frame

    def _no_data_frame(self, timestamp: int) -> EncodedFrame:
        return EncodedFrame(
            codec=self.codec,
            frame_type=15,
            quality=False,
            bit_length=0,
            data=b"",
            media_timestamp=timestamp,
            provenance=CaptureProvenance(),
        )

    def _commit_frame(self, frame: EncodedFrame) -> Iterator[tuple]:
        missing_timestamps = range(0)
        missing_count = 0
        if self._last_committed_timestamp is not None:
            expected = self._last_committed_timestamp + self._definition.timestamp_step
            if expected < frame.media_timestamp:
                missing_timestamps = range(
                    expected,
                    frame.media_timestamp,
                    self._definition.timestamp_step,
                )
                missing_count = len(missing_timestamps)
                self._gap_count += missing_count
        self._last_committed_timestamp = frame.media_timestamp
        if self.gap_policy is GapPolicy.NO_DATA and missing_count:
            synthetic = ((self._no_data_frame(timestamp), True) for timestamp in missing_timestamps)
            return chain(synthetic, ((frame, False),))
        return iter(((frame, False),))

    def _commit_through(self, watermark: int) -> Iterator[tuple]:
        emitted = []
        timestamps = sorted(timestamp for timestamp in self._pending if timestamp <= watermark)
        for timestamp in timestamps:
            emitted.append(self._commit_frame(self._pending.pop(timestamp)))
        return chain.from_iterable(emitted)

    def _prepare_output(self, emissions: Iterator[tuple]) -> Iterator[EncodedFrame]:
        try:
            first = next(emissions)
        except StopIteration:
            return iter(())
        self._output_pending = True

        def generate() -> Iterator[EncodedFrame]:
            try:
                for frame, synthetic in chain((first,), emissions):
                    self._emitted_frame_count += 1
                    if synthetic:
                        self._inserted_no_data_count += 1
                    elif not frame.quality:
                        self._bad_quality_frame_count += 1
                    yield frame
            finally:
                self._output_pending = False

        return generate()

    def push(self, record: RtpRecord) -> Iterator[EncodedFrame]:
        """Consume one packet and stream frames made safe to commit."""

        if self._finished:
            raise RuntimeError("cannot push packets after timeline finish")
        if self._output_pending:
            raise RuntimeError("consume timeline output before pushing another packet")
        if record.flow_key != self.flow_key:
            raise ValueError("RTP record does not belong to this timeline flow")
        self._packet_count += 1

        extended_sequence = _extend_wrapping(
            record.sequence,
            self._highest_sequence,
            16,
        )
        reordered = (
            self._highest_sequence is not None and extended_sequence < self._highest_sequence
        )
        identity = self._packet_identity(record, extended_sequence)
        self._evict_committed_packet_identities()
        if identity in self._recent_packets:
            self._duplicate_packet_count += 1
            return iter(())

        extended_timestamp = _extend_wrapping(
            record.timestamp,
            self._highest_timestamp,
            32,
        )
        if len(self._recent_packet_order) >= self._packet_history_limit:
            self._packet_history_overflow_count += 1
            self._retain_diagnostic(
                "packet-history-overflow",
                "packet omitted because bounded duplicate history is full",
                record.provenance,
            )
            return iter(())
        try:
            frames = depacketize(
                record.payload,
                self.codec,
                self.payload_mode,
                media_timestamp=extended_timestamp,
                provenance=record.provenance,
            )
        except Rfc4867Error:
            self._retain_packet_identity(identity, extended_timestamp)
            self._malformed_packet_count += 1
            raise

        identity_timestamp = frames[-1].media_timestamp if frames else extended_timestamp
        self._retain_packet_identity(identity, identity_timestamp)
        if self._highest_sequence is None or extended_sequence > self._highest_sequence:
            self._highest_sequence = extended_sequence
        if reordered:
            self._reordered_packet_count += 1
        if self._highest_timestamp is None or extended_timestamp > self._highest_timestamp:
            self._highest_timestamp = extended_timestamp
        self._accepted_packet_count += 1
        had_late_frame = self._add_frames(frames)
        if had_late_frame:
            self._late_packet_count += 1
            self._retain_diagnostic(
                "late-packet",
                "packet contains media whose timestamp was already committed",
                record.provenance,
            )

        if frames:
            latest_frame_timestamp = frames[-1].media_timestamp
            if self._highest_timestamp is None or latest_frame_timestamp > self._highest_timestamp:
                self._highest_timestamp = latest_frame_timestamp
        if self._highest_timestamp is None:
            return iter(())
        watermark = (
            self._highest_timestamp - self.limits.reorder_window * self._definition.timestamp_step
        )
        return self._prepare_output(self._commit_through(watermark))

    def finish(self) -> Iterator[EncodedFrame]:
        """Commit every remaining frame in media-time order."""

        if self._output_pending:
            raise RuntimeError("consume timeline output before finishing")
        if self._finished:
            return iter(())
        self._finished = True
        if not self._pending:
            return iter(())
        return self._prepare_output(self._commit_through(max(self._pending)))

    @property
    def summary(self) -> TimelineSummary:
        """Return current immutable timeline statistics and diagnostics."""

        return TimelineSummary(
            flow_key=self.flow_key,
            codec=self.codec,
            payload_mode=self.payload_mode,
            packet_count=self._packet_count,
            accepted_packet_count=self._accepted_packet_count,
            observed_frame_count=self._observed_frame_count,
            emitted_frame_count=self._emitted_frame_count,
            bad_quality_frame_count=self._bad_quality_frame_count,
            malformed_packet_count=self._malformed_packet_count,
            duplicate_packet_count=self._duplicate_packet_count,
            reordered_packet_count=self._reordered_packet_count,
            late_packet_count=self._late_packet_count,
            overlap_frame_count=self._overlap_frame_count,
            gap_count=self._gap_count,
            inserted_no_data_count=self._inserted_no_data_count,
            packet_history_overflow_count=self._packet_history_overflow_count,
            highest_extended_sequence=self._highest_sequence,
            highest_extended_timestamp=self._highest_timestamp,
            diagnostics=tuple(self._diagnostics),
            diagnostic_overflow_count=self._diagnostic_overflow_count,
        )


class TimelineRouter:
    """Route records by flow; each output iterator must be consumed in order."""

    def __init__(
        self,
        selections: Iterable[SelectedFlow],
        *,
        gap_policy: GapPolicy = GapPolicy.OMIT,
        limits: Optional[ResourceLimits] = None,
    ) -> None:
        self._normalizers = {}
        for selection in selections:
            if selection.flow_key in self._normalizers:
                raise ValueError("duplicate selected flow")
            self._normalizers[selection.flow_key] = TimelineNormalizer(
                selection.flow_key,
                selection.codec,
                selection.payload_mode,
                gap_policy=gap_policy,
                limits=limits,
            )

    def push(self, record: RtpRecord) -> Iterator[RoutedFrame]:
        """Route a packet, returning any newly committed tagged frames."""

        normalizer = self._normalizers.get(record.flow_key)
        if normalizer is None:
            return iter(())
        return _route_frames(record.flow_key, normalizer.push(record))

    def finish(self) -> Iterator[RoutedFrame]:
        """Flush every selected timeline without combining their frames."""

        if any(normalizer._output_pending for normalizer in self._normalizers.values()):
            raise RuntimeError("consume timeline output before finishing")

        def generate() -> Iterator[RoutedFrame]:
            for flow_key, normalizer in self._normalizers.items():
                yield from _route_frames(flow_key, normalizer.finish())

        return generate()

    @property
    def summaries(self) -> Tuple[TimelineSummary, ...]:
        """Return independent summaries in selection order."""

        return tuple(normalizer.summary for normalizer in self._normalizers.values())
