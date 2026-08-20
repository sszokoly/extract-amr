"""Structured errors returned by capture and codec processing."""

from __future__ import annotations

from typing import Any, Mapping, Optional, Sequence, Tuple

from .models import CaptureProvenance


class ExtractAmrError(Exception):
    """Base error carrying a stable code, details, and capture location."""

    code = "extract-amr-error"

    def __init__(
        self,
        message: str,
        *,
        provenance: Optional[CaptureProvenance] = None,
        details: Optional[Mapping[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.provenance = provenance
        self.details = dict(details or {})

    def __str__(self) -> str:
        if self.provenance is None or self.provenance.packet_number is None:
            return self.message
        return f"{self.message} (capture packet {self.provenance.packet_number})"


class CaptureInputError(ExtractAmrError):
    """The capture source cannot be read or is unsupported."""

    code = "capture-input"


class SelectionError(ExtractAmrError):
    """An explicit selector does not resolve to valid media."""

    code = "selection"


class AmbiguousSelectionError(SelectionError):
    """More than one valid candidate remains for a required selection."""

    code = "ambiguous-selection"

    def __init__(
        self,
        message: str,
        candidates: Sequence[Any],
        *,
        details: Optional[Mapping[str, Any]] = None,
    ) -> None:
        error_details = dict(details or {})
        error_details["candidate_count"] = len(candidates)
        super().__init__(message, details=error_details)
        self.candidates: Tuple[Any, ...] = tuple(candidates)


class UnsupportedFormatError(ExtractAmrError):
    """The requested codec, framing, or RFC option is unsupported."""

    code = "unsupported-format"


class RtpParseError(ExtractAmrError):
    """A selected UDP payload contains malformed RTP."""

    code = "malformed-rtp"


class Rfc4867Error(ExtractAmrError):
    """A selected RTP payload contains malformed RFC 4867 data."""

    code = "malformed-rfc4867"
