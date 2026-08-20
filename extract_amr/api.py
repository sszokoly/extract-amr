"""Public streaming inspection and extraction orchestration."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from os import PathLike
from typing import (
    BinaryIO,
    Callable,
    Dict,
    Iterable,
    Iterator,
    Mapping,
    Optional,
    Tuple,
    Union,
    cast,
)

from .bits import BIT_BACKEND
from .capture import CaptureSource, _CaptureCounts, iter_udp_records
from .codec import codec_definition
from .discovery import candidate_identifier, discover_candidates, select_candidates
from .errors import CaptureInputError, ExtractAmrError, Rfc4867Error, RtpParseError, SelectionError
from .models import (
    CaptureProvenance,
    Codec,
    EncodedFrame,
    ExtractionReport,
    FlowKey,
    FlowSelector,
    GapPolicy,
    InspectionReport,
    MalformedPolicy,
    PayloadMode,
    ResourceLimits,
    RtpRecord,
    SelectedFlow,
    TimelineDiagnostic,
)
from .rtp import parse_rtp
from .storage import serialize_storage_frame
from .timeline import TimelineNormalizer

OutputTarget = BinaryIO
OutputFactory = Callable[[SelectedFlow], OutputTarget]
FlowOutputs = Union[Mapping[FlowKey, OutputTarget], OutputFactory]


@dataclass
class _InspectionState:
    rtp_packet_count: int = 0
    malformed_rtp_count: int = 0
    diagnostics: list = field(default_factory=list)
    diagnostic_overflow_count: int = 0


@dataclass
class _FlowState:
    normalizer: TimelineNormalizer
    selected_rtp_packet_count: int = 0
    malformed_rtp_count: int = 0
    diagnostics: list = field(default_factory=list)
    diagnostic_overflow_count: int = 0
    first_packet_number: Optional[int] = None


def _is_reopenable_path(source: CaptureSource) -> bool:
    return isinstance(source, (str, PathLike))


def _retain_error(
    diagnostics: list,
    state: object,
    error: ExtractAmrError,
    limits: ResourceLimits,
) -> None:
    if len(diagnostics) < limits.max_diagnostics:
        diagnostics.append(
            TimelineDiagnostic(
                reason=str(error.details.get("reason", error.code)),
                message=error.message,
                provenance=error.provenance or CaptureProvenance(),
            ),
        )
    else:
        state.diagnostic_overflow_count += 1


def _inspection_rtp_records(
    source: CaptureSource,
    selector: FlowSelector,
    limits: ResourceLimits,
    counts: _CaptureCounts,
    state: _InspectionState,
) -> Iterator[RtpRecord]:
    for udp in iter_udp_records(source, selector, _counts=counts):
        try:
            record = parse_rtp(udp)
        except RtpParseError as error:
            state.malformed_rtp_count += 1
            _retain_error(state.diagnostics, state, error, limits)
            continue
        if record is not None:
            state.rtp_packet_count += 1
            yield record


def inspect_pcap(
    source: CaptureSource,
    *,
    selector: Optional[FlowSelector] = None,
    limits: Optional[ResourceLimits] = None,
) -> InspectionReport:
    """Stream one capture pass and return bounded deterministic evidence."""

    selected = selector or FlowSelector()
    bounds = limits or ResourceLimits()
    counts = _CaptureCounts()
    state = _InspectionState()
    discovery = discover_candidates(
        _inspection_rtp_records(source, selected, bounds, counts, state),
        selector=selected,
        limits=bounds,
    )
    if counts.packet_count == 0:
        raise CaptureInputError("capture contains no packets")
    probe_diagnostics = tuple(
        TimelineDiagnostic(
            reason=diagnostic.reason,
            message=diagnostic.message,
            provenance=diagnostic.provenance,
        )
        for diagnostic in discovery.diagnostics
    )
    diagnostics = tuple(state.diagnostics) + probe_diagnostics
    overflow = state.diagnostic_overflow_count + discovery.diagnostic_overflow_count
    if len(diagnostics) > bounds.max_diagnostics:
        overflow += len(diagnostics) - bounds.max_diagnostics
        diagnostics = diagnostics[: bounds.max_diagnostics]
    discovery = replace(
        discovery,
        diagnostics=(),
        diagnostic_overflow_count=overflow,
    )
    return InspectionReport(
        discovery=discovery,
        capture_packet_count=counts.packet_count,
        udp_packet_count=counts.udp_packet_count,
        rtp_packet_count=state.rtp_packet_count,
        malformed_rtp_count=state.malformed_rtp_count,
        diagnostics=diagnostics,
        diagnostic_overflow_count=overflow,
    )


def _flow_from_selector(selector: FlowSelector) -> FlowKey:
    if not selector.is_complete:
        raise ValueError("a complete flow selector is required")
    return FlowKey(
        src_address=cast(str, selector.src_address),
        dst_address=cast(str, selector.dst_address),
        src_port=cast(int, selector.src_port),
        dst_port=cast(int, selector.dst_port),
        ssrc=cast(int, selector.ssrc),
        payload_type=cast(int, selector.payload_type),
    )


def _explicit_selection(
    selector: FlowSelector,
    codec: Codec,
    payload_mode: PayloadMode,
) -> SelectedFlow:
    flow_key = _flow_from_selector(selector)
    return SelectedFlow(
        candidate_id=candidate_identifier(flow_key, 0),
        flow_key=flow_key,
        codec=codec,
        payload_mode=payload_mode,
        first_packet_number=0,
    )


def _matching_malformed_targets(
    states: Mapping[FlowKey, _FlowState],
    error: RtpParseError,
    src_address: str,
    dst_address: str,
    src_port: int,
    dst_port: int,
) -> Tuple[_FlowState, ...]:
    error_flow = error.details.get("flow_key")
    if isinstance(error_flow, FlowKey):
        state = states.get(error_flow)
        return (state,) if state is not None else ()
    endpoint_matches = tuple(
        state
        for key, state in states.items()
        if (
            key.src_address == src_address
            and key.dst_address == dst_address
            and key.src_port == src_port
            and key.dst_port == dst_port
        )
    )
    if len(endpoint_matches) == 1:
        return endpoint_matches
    return ()


def _new_flow_states(
    selections: Iterable[SelectedFlow],
    gap_policy: GapPolicy,
    limits: ResourceLimits,
) -> Dict[FlowKey, _FlowState]:
    return {
        selection.flow_key: _FlowState(
            TimelineNormalizer(
                selection.flow_key,
                selection.codec,
                selection.payload_mode,
                gap_policy=gap_policy,
                limits=limits,
            ),
        )
        for selection in selections
    }


def _iter_routed_frames(
    source: CaptureSource,
    selections: Tuple[SelectedFlow, ...],
    selector: FlowSelector,
    gap_policy: GapPolicy,
    malformed_policy: MalformedPolicy,
    limits: ResourceLimits,
    counts: _CaptureCounts,
    states: Dict[FlowKey, _FlowState],
) -> Iterator[Tuple[FlowKey, EncodedFrame]]:
    for udp in iter_udp_records(source, selector, _counts=counts):
        try:
            record = parse_rtp(udp)
        except RtpParseError as error:
            targets = _matching_malformed_targets(
                states,
                error,
                udp.src_address,
                udp.dst_address,
                udp.src_port,
                udp.dst_port,
            )
            for state in targets:
                state.malformed_rtp_count += 1
                _retain_error(state.diagnostics, state, error, limits)
            if targets and malformed_policy is MalformedPolicy.STRICT:
                raise
            continue
        if record is None:
            continue
        state = states.get(record.flow_key)
        if state is None:
            continue
        state.selected_rtp_packet_count += 1
        packet_number = record.provenance.packet_number
        if state.first_packet_number is None and packet_number is not None:
            state.first_packet_number = packet_number
        try:
            frames = state.normalizer.push(record)
        except Rfc4867Error as error:
            _retain_error(state.diagnostics, state, error, limits)
            if malformed_policy is MalformedPolicy.STRICT:
                raise
            continue
        for frame in frames:
            yield record.flow_key, frame

    for selection in selections:
        state = states[selection.flow_key]
        for frame in state.normalizer.finish():
            yield selection.flow_key, frame


def iter_frames(
    source: CaptureSource,
    selection: SelectedFlow,
    *,
    gap_policy: GapPolicy = GapPolicy.OMIT,
    malformed_policy: MalformedPolicy = MalformedPolicy.SKIP,
    limits: Optional[ResourceLimits] = None,
) -> Iterator[EncodedFrame]:
    """Stream normalized encoded frames without requiring storage output."""

    bounds = limits or ResourceLimits()
    states = _new_flow_states((selection,), gap_policy, bounds)
    counts = _CaptureCounts()
    selector = _selector_for_flow(selection.flow_key)
    for _, frame in _iter_routed_frames(
        source,
        (selection,),
        selector,
        gap_policy,
        malformed_policy,
        bounds,
        counts,
        states,
    ):
        yield frame


def _selector_for_flow(flow_key: FlowKey) -> FlowSelector:
    return FlowSelector(
        src_address=flow_key.src_address,
        dst_address=flow_key.dst_address,
        src_port=flow_key.src_port,
        dst_port=flow_key.dst_port,
        ssrc=flow_key.ssrc,
        payload_type=flow_key.payload_type,
    )


def _output_stream(target: OutputTarget) -> BinaryIO:
    if not hasattr(target, "write"):
        raise ValueError("output must be a caller-owned writable binary stream")
    return cast(BinaryIO, target)


def _write_all(stream: BinaryIO, data: bytes) -> None:
    remaining = memoryview(data)
    while remaining:
        written = stream.write(remaining)
        if written is None or written <= 0:
            raise OSError("output stream did not accept serialized bytes")
        remaining = remaining[written:]


def _combined_diagnostics(
    state: _FlowState,
    limits: ResourceLimits,
) -> Tuple[Tuple[TimelineDiagnostic, ...], int]:
    summary = state.normalizer.summary
    diagnostics = list(state.diagnostics) + list(summary.diagnostics)
    diagnostics.sort(
        key=lambda item: (
            item.provenance.packet_number if item.provenance.packet_number is not None else 2**63,
            item.reason,
        ),
    )
    overflow = state.diagnostic_overflow_count + summary.diagnostic_overflow_count
    if len(diagnostics) > limits.max_diagnostics:
        overflow += len(diagnostics) - limits.max_diagnostics
        diagnostics = diagnostics[: limits.max_diagnostics]
    return tuple(diagnostics), overflow


def _report(
    selection: SelectedFlow,
    state: _FlowState,
    counts: _CaptureCounts,
    capture_pass_count: int,
    limits: ResourceLimits,
) -> ExtractionReport:
    summary = state.normalizer.summary
    diagnostics, diagnostic_overflow = _combined_diagnostics(state, limits)
    if selection.first_packet_number == 0 and state.first_packet_number is not None:
        selection = replace(
            selection,
            candidate_id=candidate_identifier(
                selection.flow_key,
                state.first_packet_number,
            ),
            first_packet_number=state.first_packet_number,
        )
    return ExtractionReport(
        selected_flow=selection,
        output_path=None,
        bit_backend=BIT_BACKEND.name,
        bit_backend_fallback_reason=BIT_BACKEND.fallback_reason,
        capture_pass_count=capture_pass_count,
        capture_packet_count=counts.packet_count,
        udp_packet_count=counts.udp_packet_count,
        selected_rtp_packet_count=state.selected_rtp_packet_count,
        emitted_frame_count=summary.emitted_frame_count,
        bad_quality_frame_count=summary.bad_quality_frame_count,
        duplicate_packet_count=summary.duplicate_packet_count,
        gap_count=summary.gap_count,
        inserted_no_data_count=summary.inserted_no_data_count,
        reordered_packet_count=summary.reordered_packet_count,
        late_packet_count=summary.late_packet_count,
        overlap_frame_count=summary.overlap_frame_count,
        malformed_packet_count=(state.malformed_rtp_count + summary.malformed_packet_count),
        packet_history_overflow_count=summary.packet_history_overflow_count,
        diagnostics=diagnostics,
        diagnostic_overflow_count=diagnostic_overflow,
    )


def _resolve_extraction(
    source: CaptureSource,
    selector: FlowSelector,
    codec: Optional[Codec],
    payload_mode: Optional[PayloadMode],
    limits: ResourceLimits,
) -> Tuple[Tuple[SelectedFlow, ...], int]:
    if selector.is_complete and codec is not None and payload_mode is not None:
        return (_explicit_selection(selector, codec, payload_mode),), 1
    if not _is_reopenable_path(source):
        raise CaptureInputError(
            "automatic discovery requires a reopenable capture path",
        )
    inspection = inspect_pcap(source, selector=selector, limits=limits)
    return (
        select_candidates(
            inspection.discovery,
            selector=selector,
            codec=codec,
            payload_mode=payload_mode,
        ),
        2,
    )


def extract_pcap(
    source: CaptureSource,
    output: OutputTarget,
    *,
    selector: Optional[FlowSelector] = None,
    codec: Optional[Codec] = None,
    payload_mode: Optional[PayloadMode] = None,
    gap_policy: GapPolicy = GapPolicy.OMIT,
    malformed_policy: MalformedPolicy = MalformedPolicy.SKIP,
    limits: Optional[ResourceLimits] = None,
) -> ExtractionReport:
    """Extract one resolved flow in one pass, or discovery plus one pass."""

    selected = selector or FlowSelector()
    bounds = limits or ResourceLimits()
    selections, pass_count = _resolve_extraction(
        source,
        selected,
        codec,
        payload_mode,
        bounds,
    )
    if len(selections) != 1:
        raise SelectionError(
            "multiple selected flows require extract_flows",
            details={"selected_flow_count": len(selections)},
        )
    selection = selections[0]
    states = _new_flow_states(selections, gap_policy, bounds)
    counts = _CaptureCounts()
    stream = _output_stream(output)
    _write_all(stream, codec_definition(selection.codec).storage_header)
    for _, frame in _iter_routed_frames(
        source,
        selections,
        selected,
        gap_policy,
        malformed_policy,
        bounds,
        counts,
        states,
    ):
        _write_all(stream, serialize_storage_frame(frame))
    state = states[selection.flow_key]
    if state.selected_rtp_packet_count == 0:
        raise SelectionError("selected flow has no RTP packets in the capture")
    if state.normalizer.summary.accepted_packet_count == 0:
        raise SelectionError(
            "selected flow has no payload valid for the requested codec and mode",
        )
    return _report(
        selection,
        state,
        counts,
        pass_count,
        bounds,
    )


def extract_flows(
    source: CaptureSource,
    outputs: FlowOutputs,
    *,
    selector: FlowSelector,
    codec: Optional[Codec] = None,
    payload_mode: Optional[PayloadMode] = None,
    gap_policy: GapPolicy = GapPolicy.OMIT,
    malformed_policy: MalformedPolicy = MalformedPolicy.SKIP,
    limits: Optional[ResourceLimits] = None,
) -> Tuple[ExtractionReport, ...]:
    """Discover and extract every resolved port-selected full flow."""

    bounds = limits or ResourceLimits()
    selections, pass_count = _resolve_extraction(
        source,
        selector,
        codec,
        payload_mode,
        bounds,
    )
    if callable(outputs):
        resolved_outputs = {selection.flow_key: outputs(selection) for selection in selections}
    else:
        resolved_outputs = outputs
    missing = tuple(
        selection.flow_key for selection in selections if selection.flow_key not in resolved_outputs
    )
    if missing:
        raise SelectionError(
            "an output is required for every selected flow",
            details={"missing_output_flows": missing},
        )
    selected_outputs = tuple(resolved_outputs[selection.flow_key] for selection in selections)
    for output in selected_outputs:
        _output_stream(output)
    if len({id(output) for output in selected_outputs}) != len(selected_outputs):
        raise SelectionError("every selected flow requires an independent output stream")

    states = _new_flow_states(selections, gap_policy, bounds)
    counts = _CaptureCounts()
    streams = {
        selection.flow_key: _output_stream(resolved_outputs[selection.flow_key])
        for selection in selections
    }
    for selection in selections:
        _write_all(
            streams[selection.flow_key],
            codec_definition(selection.codec).storage_header,
        )
    for flow_key, frame in _iter_routed_frames(
        source,
        selections,
        selector,
        gap_policy,
        malformed_policy,
        bounds,
        counts,
        states,
    ):
        _write_all(streams[flow_key], serialize_storage_frame(frame))

    reports = []
    for selection in selections:
        state = states[selection.flow_key]
        if state.selected_rtp_packet_count == 0:
            raise SelectionError(
                f"selected flow {selection.candidate_id} has no RTP packets",
            )
        if state.normalizer.summary.accepted_packet_count == 0:
            raise SelectionError(
                f"selected flow {selection.candidate_id} has no valid payloads",
            )
        reports.append(
            _report(
                selection,
                state,
                counts,
                pass_count,
                bounds,
            ),
        )
    return tuple(reports)
