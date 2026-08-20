"""Bounded exact format discovery and deterministic flow selection."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

from .errors import AmbiguousSelectionError, Rfc4867Error, SelectionError
from .models import (
    Codec,
    DiscoveryResult,
    FlowCandidate,
    FlowKey,
    FlowSelector,
    FormatEvidence,
    PayloadMode,
    PayloadProbe,
    ProbeDiagnostic,
    ResourceLimits,
    RtpRecord,
    SelectedFlow,
)
from .rfc4867 import depacketize

_FORMATS = tuple((codec, mode) for codec in Codec for mode in PayloadMode)


@dataclass
class _EvidenceState:
    success_count: int = 0
    failure_count: int = 0
    first_rejection_reason: Optional[str] = None


@dataclass
class _CandidateState:
    candidate_id: str
    flow_key: FlowKey
    first_packet_number: int
    sampled_packet_count: int
    sample_overflow_count: int
    formats: Dict[Tuple[Codec, PayloadMode], _EvidenceState]


@dataclass
class _DiagnosticState:
    flow_key: FlowKey
    codec: Codec
    payload_mode: PayloadMode
    reason: str
    message: str
    record: RtpRecord


def probe_payload(payload: bytes) -> Tuple[PayloadProbe, ...]:
    """Validate one payload against every supported codec/mode pair."""

    results = []
    for codec, mode in _FORMATS:
        try:
            frames = depacketize(payload, codec, mode)
        except Rfc4867Error as error:
            results.append(
                PayloadProbe(
                    codec=codec,
                    payload_mode=mode,
                    success=False,
                    rejection_reason=str(error.details.get("reason", error.code)),
                    rejection_message=error.message,
                ),
            )
        else:
            results.append(
                PayloadProbe(
                    codec=codec,
                    payload_mode=mode,
                    success=True,
                    frame_count=len(frames),
                ),
            )
    return tuple(results)


def candidate_identifier(flow_key: FlowKey, first_packet_number: int) -> str:
    """Return a stable identifier derived from flow identity and position."""

    material = "|".join(
        (
            str(first_packet_number),
            flow_key.src_address,
            str(flow_key.src_port),
            flow_key.dst_address,
            str(flow_key.dst_port),
            str(flow_key.ssrc),
            str(flow_key.payload_type),
        ),
    ).encode("utf-8")
    digest = hashlib.sha256(material).hexdigest()[:16]
    return f"flow-{first_packet_number:08d}-{digest}"


def _new_candidate(record: RtpRecord, packet_number: int) -> _CandidateState:
    return _CandidateState(
        candidate_id=candidate_identifier(record.flow_key, packet_number),
        flow_key=record.flow_key,
        first_packet_number=packet_number,
        sampled_packet_count=0,
        sample_overflow_count=0,
        formats={key: _EvidenceState() for key in _FORMATS},
    )


def _candidate_sort_key(state: _CandidateState) -> tuple:
    key = state.flow_key
    return (
        state.first_packet_number,
        key.src_address,
        key.src_port,
        key.dst_address,
        key.dst_port,
        key.ssrc,
        key.payload_type,
    )


def _freeze_candidate(state: _CandidateState) -> FlowCandidate:
    formats = tuple(
        FormatEvidence(
            codec=codec,
            payload_mode=mode,
            success_count=state.formats[(codec, mode)].success_count,
            failure_count=state.formats[(codec, mode)].failure_count,
            first_rejection_reason=state.formats[(codec, mode)].first_rejection_reason,
        )
        for codec, mode in _FORMATS
    )
    return FlowCandidate(
        candidate_id=state.candidate_id,
        flow_key=state.flow_key,
        first_packet_number=state.first_packet_number,
        sampled_packet_count=state.sampled_packet_count,
        sample_overflow_count=state.sample_overflow_count,
        formats=formats,
    )


def discover_candidates(
    records: Iterable[RtpRecord],
    selector: Optional[FlowSelector] = None,
    limits: Optional[ResourceLimits] = None,
) -> DiscoveryResult:
    """Probe a stream of RTP records with bounded retained state."""

    selected = selector or FlowSelector()
    bounds = limits or ResourceLimits()
    states: Dict[FlowKey, _CandidateState] = {}
    diagnostic_states: List[_DiagnosticState] = []
    observed_count = 0
    sampled_count = 0
    candidate_overflow_count = 0
    sample_overflow_count = 0
    diagnostic_overflow_count = 0

    for stream_position, record in enumerate(records, start=1):
        if not selected.matches_flow(record.flow_key):
            continue
        observed_count += 1
        state = states.get(record.flow_key)
        if state is None:
            if len(states) >= bounds.max_candidates:
                candidate_overflow_count += 1
                continue
            packet_number = record.provenance.packet_number
            state = _new_candidate(
                record,
                packet_number if packet_number is not None else stream_position,
            )
            states[record.flow_key] = state
        else:
            packet_number = record.provenance.packet_number
            if packet_number is not None and packet_number < state.first_packet_number:
                state.first_packet_number = packet_number
                state.candidate_id = candidate_identifier(record.flow_key, packet_number)

        if state.sampled_packet_count >= bounds.max_samples_per_flow:
            state.sample_overflow_count += 1
            sample_overflow_count += 1
            continue

        state.sampled_packet_count += 1
        sampled_count += 1
        for result in probe_payload(record.payload):
            evidence = state.formats[(result.codec, result.payload_mode)]
            if result.success:
                evidence.success_count += 1
                continue
            evidence.failure_count += 1
            if evidence.first_rejection_reason is None:
                evidence.first_rejection_reason = result.rejection_reason
            if len(diagnostic_states) < bounds.max_diagnostics:
                diagnostic_states.append(
                    _DiagnosticState(
                        flow_key=record.flow_key,
                        codec=result.codec,
                        payload_mode=result.payload_mode,
                        reason=result.rejection_reason or "malformed-rfc4867",
                        message=result.rejection_message or "payload rejected",
                        record=record,
                    ),
                )
            else:
                diagnostic_overflow_count += 1

    candidates = tuple(
        _freeze_candidate(state) for state in sorted(states.values(), key=_candidate_sort_key)
    )
    diagnostics = tuple(
        ProbeDiagnostic(
            candidate_id=states[item.flow_key].candidate_id,
            codec=item.codec,
            payload_mode=item.payload_mode,
            reason=item.reason,
            message=item.message,
            provenance=item.record.provenance,
        )
        for item in diagnostic_states
    )
    return DiscoveryResult(
        candidates=candidates,
        diagnostics=diagnostics,
        observed_packet_count=observed_count,
        sampled_packet_count=sampled_count,
        candidate_overflow_count=candidate_overflow_count,
        sample_overflow_count=sample_overflow_count,
        diagnostic_overflow_count=diagnostic_overflow_count,
    )


def _selector_fields(selector: FlowSelector) -> dict:
    values = (
        ("src_address", selector.src_address),
        ("dst_address", selector.dst_address),
        ("src_port", selector.src_port),
        ("dst_port", selector.dst_port),
        ("ssrc", selector.ssrc),
        ("payload_type", selector.payload_type),
    )
    return {name: value for name, value in values if value is not None}


def _format_fields(
    codec: Optional[Codec],
    payload_mode: Optional[PayloadMode],
) -> dict:
    fields = {}
    if codec is not None:
        fields["codec"] = codec.value
    if payload_mode is not None:
        fields["payload_mode"] = payload_mode.value
    return fields


def _candidate_fields(candidate: FlowCandidate) -> dict:
    key = candidate.flow_key
    return {
        "candidate_id": candidate.candidate_id,
        "src_address": key.src_address,
        "dst_address": key.dst_address,
        "src_port": key.src_port,
        "dst_port": key.dst_port,
        "ssrc": key.ssrc,
        "payload_type": key.payload_type,
        "formats": tuple(
            {
                "codec": evidence.codec.value,
                "payload_mode": evidence.payload_mode.value,
                "valid": evidence.is_valid,
                "success_count": evidence.success_count,
                "failure_count": evidence.failure_count,
                "first_rejection_reason": evidence.first_rejection_reason,
            }
            for evidence in candidate.formats
        ),
    }


def _matching_formats(
    candidate: FlowCandidate,
    codec: Optional[Codec],
    payload_mode: Optional[PayloadMode],
) -> Tuple[FormatEvidence, ...]:
    return tuple(
        evidence
        for evidence in candidate.valid_formats
        if (codec is None or evidence.codec is codec)
        and (payload_mode is None or evidence.payload_mode is payload_mode)
    )


def _selection(candidate: FlowCandidate, evidence: FormatEvidence) -> SelectedFlow:
    return SelectedFlow(
        candidate_id=candidate.candidate_id,
        flow_key=candidate.flow_key,
        codec=evidence.codec,
        payload_mode=evidence.payload_mode,
        first_packet_number=candidate.first_packet_number,
    )


def _selection_details(
    result: DiscoveryResult,
    selector: FlowSelector,
    codec: Optional[Codec],
    payload_mode: Optional[PayloadMode],
) -> dict:
    return {
        "selector": _selector_fields(selector),
        "requested_format": _format_fields(codec, payload_mode),
        "available_candidates": tuple(
            _candidate_fields(candidate) for candidate in result.candidates
        ),
        "candidate_overflow_count": result.candidate_overflow_count,
        "sample_overflow_count": result.sample_overflow_count,
        "diagnostic_overflow_count": result.diagnostic_overflow_count,
    }


def _raise_no_selection(
    result: DiscoveryResult,
    selector: FlowSelector,
    codec: Optional[Codec],
    payload_mode: Optional[PayloadMode],
    *,
    format_mismatch: bool = False,
    unresolved_candidate: Optional[FlowCandidate] = None,
) -> None:
    details = _selection_details(result, selector, codec, payload_mode)
    if unresolved_candidate is not None:
        details["unresolved_candidate"] = _candidate_fields(unresolved_candidate)
    if format_mismatch:
        if unresolved_candidate is None:
            message = "the requested codec or payload mode does not match the selected flow"
        else:
            message = (
                "codec and payload mode cannot be resolved for flow "
                f"{unresolved_candidate.candidate_id}"
            )
    elif selector.is_port_filter:
        port_filters = {
            name: value
            for name, value in (
                ("src_port", selector.src_port),
                ("dst_port", selector.dst_port),
            )
            if value is not None
        }
        details["unmatched_port_filters"] = port_filters
        filters = ", ".join(f"{name}={value}" for name, value in port_filters.items())
        message = f"no unambiguous media flow matches UDP port filters: {filters}"
    else:
        message = "no valid media flow matches the requested selector"
    raise SelectionError(message, details=details)


def _raise_ambiguity(
    message: str,
    selections: Iterable[SelectedFlow],
    details: dict,
) -> None:
    candidates = tuple(selections)
    details["candidate_fields"] = tuple(
        _candidate_fields_for_selection(selection) for selection in candidates
    )
    raise AmbiguousSelectionError(message, candidates, details=details)


def _candidate_fields_for_selection(selection: SelectedFlow) -> dict:
    key = selection.flow_key
    return {
        "candidate_id": selection.candidate_id,
        "src_address": key.src_address,
        "dst_address": key.dst_address,
        "src_port": key.src_port,
        "dst_port": key.dst_port,
        "ssrc": key.ssrc,
        "payload_type": key.payload_type,
        "codec": selection.codec.value,
        "payload_mode": selection.payload_mode.value,
    }


def select_candidates(
    result: DiscoveryResult,
    selector: Optional[FlowSelector] = None,
    codec: Optional[Codec] = None,
    payload_mode: Optional[PayloadMode] = None,
) -> Tuple[SelectedFlow, ...]:
    """Resolve bounded discovery evidence according to selection rules."""

    selected = selector or FlowSelector()
    if result.candidate_overflow_count:
        details = _selection_details(result, selected, codec, payload_mode)
        raise SelectionError(
            "candidate limit was exceeded; increase max_candidates before selection",
            details=details,
        )

    matching_candidates = tuple(
        candidate for candidate in result.candidates if selected.matches_flow(candidate.flow_key)
    )
    if not matching_candidates:
        _raise_no_selection(result, selected, codec, payload_mode)

    details = _selection_details(result, selected, codec, payload_mode)
    if selected.is_port_filter:
        resolved = []
        for candidate in matching_candidates:
            formats = _matching_formats(candidate, codec, payload_mode)
            if not formats:
                _raise_no_selection(
                    result,
                    selected,
                    codec,
                    payload_mode,
                    format_mismatch=True,
                    unresolved_candidate=candidate,
                )
            options = tuple(_selection(candidate, evidence) for evidence in formats)
            if len(options) > 1:
                _raise_ambiguity(
                    f"flow {candidate.candidate_id} has ambiguous codec or payload mode",
                    options,
                    details,
                )
            resolved.append(options[0])
        return tuple(resolved)

    matching_flows = tuple(
        candidate for candidate in matching_candidates if candidate.valid_formats
    )
    compatible = tuple(
        (candidate, _matching_formats(candidate, codec, payload_mode))
        for candidate in matching_flows
    )
    compatible = tuple(item for item in compatible if item[1])
    if not compatible:
        _raise_no_selection(
            result,
            selected,
            codec,
            payload_mode,
            format_mismatch=True,
            unresolved_candidate=matching_candidates[0]
            if not matching_flows and len(matching_candidates) == 1
            else None,
        )
    if len(compatible) > 1:
        options = (
            _selection(candidate, evidence)
            for candidate, formats in compatible
            for evidence in formats
        )
        _raise_ambiguity(
            "multiple media flows match; specify a complete directional flow",
            options,
            details,
        )

    candidate, formats = compatible[0]
    options = tuple(_selection(candidate, evidence) for evidence in formats)
    if len(options) > 1:
        _raise_ambiguity(
            "codec or payload mode is ambiguous; specify --codec and --mode",
            options,
            details,
        )
    return options
